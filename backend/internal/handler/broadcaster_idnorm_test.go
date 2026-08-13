package handler

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// One audit has TWO string forms in this system, and both are in active use:
//
//	generateID() (service/source_service.go) returns fmt.Sprintf("%x", h[:16]) —
//	32 hex chars, NO dashes. That value is what POST /api/audits returns in its
//	201 body and what DispatchAudit registers the run under.
//
//	Postgres stores it in a `uuid` column, which accepts the undashed form and
//	renders it back DASHED. Every client that reads the audit from the API (the
//	SPA: /api/audits, /api/audits/:id) therefore holds the dashed form.
//
// The run registry was keyed on whichever form the caller happened to hold, so a
// dashed-id stream request could not find a run registered under the undashed
// id. The stream handler then concluded "no run owns it", marked the LIVE audit
// FAILED, and persistResultsWithError revoked the run's broker token — after
// which every LLM call in that audit returned 401 token_revoked. Observed in the
// field: opening the results page mid-run cost the audit 10 of its 18
// llm-provenance findings and produced 312 judge_error coverage stamps.

const (
	undashedID = "85f45b9dd488e684c73689e5b3759d3c"
	dashedID   = "85f45b9d-d488-e684-c736-89e5b3759d3c"
)

// The registry must treat both spellings of one id as the same run.
func TestRegistryKeyIsIDFormAgnostic(t *testing.T) {
	r := newBroadcastRegistry()

	if _, ok := r.Open(undashedID, 8192); !ok {
		t.Fatal("first Open must win")
	}
	if _, ok := r.Get(dashedID); !ok {
		t.Error("a run registered under the undashed id must be findable by the dashed id")
	}
	// Single-flight must also hold across forms, or two producers could run one
	// audit and double-fire the whole persist side-effect set.
	if _, ok := r.Open(dashedID, 8192); ok {
		t.Error("Open with the other id form must NOT create a second run for the same audit")
	}

	// And symmetrically.
	r2 := newBroadcastRegistry()
	if _, ok := r2.Open(dashedID, 8192); !ok {
		t.Fatal("Open (dashed) must win")
	}
	if _, ok := r2.Get(undashedID); !ok {
		t.Error("a run registered under the dashed id must be findable by the undashed id")
	}
}

// Release must resolve the same entry regardless of which form is passed,
// otherwise a run would never be closed and its history would leak for the
// process lifetime.
func TestRegistryReleaseIsIDFormAgnostic(t *testing.T) {
	r := newBroadcastRegistry()
	b, ok := r.Open(undashedID, 8192)
	if !ok {
		t.Fatal("Open must win")
	}
	r.Release(dashedID, 0) // immediate eviction, via the OTHER form
	if b2, ok := r.Get(undashedID); ok {
		t.Errorf("Release(dashed) must have evicted the run opened as undashed (still present: %v)", b2)
	}
	if !b.Closed() {
		t.Error("Release(dashed) must have closed the broadcaster")
	}
}

// Normalisation must not merge DIFFERENT audits.
func TestRegistryDoesNotCollideDistinctAudits(t *testing.T) {
	r := newBroadcastRegistry()
	if _, ok := r.Open("aaaaaaaabbbbccccddddeeeeeeeeeeee", 8192); !ok {
		t.Fatal("first Open must win")
	}
	if _, ok := r.Open("ffffffffbbbbccccddddeeeeeeeeeeee", 8192); !ok {
		t.Error("a genuinely different audit id must get its own run")
	}
	if _, ok := r.Get("11111111-2222-3333-4444-555555555555"); ok {
		t.Error("an unrelated id must not resolve to someone else's run")
	}
}

// End-to-end through the handler: the exact field failure. A live run is
// dispatched under the undashed id (as POST /api/audits does); the SPA then
// streams the dashed id. It must ATTACH, and must NOT mark the audit failed.
func TestStreamWithDashedIDAttachesToRunDispatchedUndashed(t *testing.T) {
	t.Setenv("VULTURE_AUDIT_AUTODISPATCH", "true")

	var failedStatus string
	svc := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			// Postgres resolves either spelling, so the audit is always found —
			// which is exactly why the registry miss was mistaken for an orphan.
			return &model.Audit{ID: dashedID, Status: model.AuditStatusRunning, Types: []string{"cwe"}}, nil
		},
		updateFn: func(a *model.Audit) error {
			if a.Status == model.AuditStatusFailed {
				failedStatus = a.DegradedReason
			}
			return nil
		},
	}
	h := NewStreamHandler(svc, &mockSourceService{}, &mockStreamService{}, nil)

	// The run is live, registered under the id form POST hands to DispatchAudit.
	b, ok := h.runs.Open(undashedID, 8192)
	if !ok {
		t.Fatal("failed to register the run")
	}
	// Give it one event so this test is about the id form, not the empty-broadcaster
	// race (which has its own test).
	b.Send(&model.AgUIEvent{Type: model.EventRunStarted, RunID: undashedID, ThreadID: "t"})

	req := httptest.NewRequest("GET", "/api/audits/"+dashedID+"/stream", nil)
	w := &flushableRecorder{ResponseRecorder: httptest.NewRecorder()}
	// Close the broadcaster so attachToRun returns instead of blocking on a live run.
	b.Close()
	h.ServeHTTP(w, req)

	if failedStatus != "" {
		t.Errorf("a LIVE run was marked failed via the dashed id: %q", failedStatus)
	}
	body := w.Body.String()
	if strings.Contains(body, "no process owns it") {
		t.Errorf("dashed-id client got the orphan notice for a live run: %q", body)
	}
}

// The genuine orphan must still be reconciled: a running row with NO registry
// entry in either form is a real restart casualty, and leaving it at `running`
// makes `vulture scan --wait` poll forever.
func TestTrueOrphanStillReconciledAfterNormalisation(t *testing.T) {
	t.Setenv("VULTURE_AUDIT_AUTODISPATCH", "true")

	var reason string
	svc := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			return &model.Audit{ID: dashedID, Status: model.AuditStatusRunning, Types: []string{"cwe"}}, nil
		},
		updateFn: func(a *model.Audit) error {
			if a.Status == model.AuditStatusFailed {
				reason = a.DegradedReason
			}
			return nil
		},
	}
	h := NewStreamHandler(svc, &mockSourceService{}, &mockStreamService{}, nil)

	req := httptest.NewRequest("GET", "/api/audits/"+dashedID+"/stream", nil)
	w := &flushableRecorder{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(w, req)

	if reason == "" {
		t.Error("a truly unowned running audit must still be reconciled to FAILED")
	}
}

// Guard the helper directly, including the shapes that must pass through
// unchanged.
func TestCanonicalRunKey(t *testing.T) {
	cases := map[string]string{
		dashedID:   undashedID,
		undashedID: undashedID,
		strings.ToUpper(dashedID): undashedID,
		"":                        "",
		"not-a-uuid":              "notauuid",
	}
	for in, want := range cases {
		if got := canonicalRunKey(in); got != want {
			t.Errorf("canonicalRunKey(%q) = %q, want %q", in, got, want)
		}
	}
}

var _ = time.Second // keep the time import honest if assertions change
