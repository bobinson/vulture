package handler

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0071 regression. Under autodispatch, POST /api/audits registers the
// run's broadcaster synchronously and THEN spawns the run goroutine, which
// blocks in drainResult for the whole scan before it emits its first event. A
// client that connects the instant it receives the 201 therefore finds the
// broadcaster present but empty. It must ATTACH to that live run — not conclude
// the audit is orphaned and mark the row FAILED.
//
// This reproduced in the field as `vulture scan` reporting `Status: failed /
// Findings: 0` for a scan that was in fact running (audit 1eab0c88): the stream
// GET raced the run, notifyOrphaned wrote status=failed and sent the client a
// fake RunFinished, and the CLI reported the bogus terminal state.
func TestStreamHandler_LiveEmptyBroadcasterIsNotOrphaned(t *testing.T) {
	t.Setenv("VULTURE_AUDIT_AUTODISPATCH", "true")

	var markedFailed bool
	svc := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			return &model.Audit{ID: id, Status: model.AuditStatusPending, Types: []string{"cwe"}}, nil
		},
		updateFn: func(a *model.Audit) error {
			if a.Status == model.AuditStatusFailed {
				markedFailed = true
			}
			return nil
		},
	}
	h := NewStreamHandler(svc, &mockSourceService{}, &mockStreamService{}, nil)

	// Autodispatch has registered the run's broadcaster; it is live (open) but
	// has emitted nothing yet — exactly the race window.
	b, ok := h.runs.Open("a-live", 8192)
	if !ok {
		t.Fatal("failed to open broadcaster for test setup")
	}
	if !b.IsEmpty() {
		t.Fatal("precondition: a freshly opened broadcaster must be empty")
	}

	// The client connects, then hangs up (canceled ctx) so attachToRun returns
	// promptly instead of blocking on a run that emits nothing in the test.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("GET", "/api/audits/a-live/stream", nil).WithContext(ctx)
	w := &flushableRecorder{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(w, req)

	if markedFailed {
		t.Fatal("live-but-empty run was wrongly marked FAILED (orphan false-positive)")
	}
	if strings.Contains(w.Body.String(), "no process owns it") {
		t.Fatalf("client received the orphan notice for a live run: %q", w.Body.String())
	}
}

// The fix must not blunt genuine orphan detection. A real backend restart loses
// the per-process registry, so a still-`running` row has NO broadcaster
// (registry miss). That case must still be reconciled to FAILED, or
// `vulture scan --wait` polls the stuck row forever.
func TestStreamHandler_TrueOrphanStillMarkedFailed(t *testing.T) {
	t.Setenv("VULTURE_AUDIT_AUTODISPATCH", "true")

	var failedReason string
	svc := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			return &model.Audit{ID: id, Status: model.AuditStatusRunning, Types: []string{"cwe"}}, nil
		},
		updateFn: func(a *model.Audit) error {
			if a.Status == model.AuditStatusFailed {
				failedReason = a.DegradedReason
			}
			return nil
		},
	}
	h := NewStreamHandler(svc, &mockSourceService{}, &mockStreamService{}, nil)

	// No broadcaster registered → registry miss → genuine orphan.
	req := httptest.NewRequest("GET", "/api/audits/a-orphan/stream", nil)
	w := &flushableRecorder{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(w, req)

	if failedReason == "" {
		t.Fatal("a truly orphaned (registry-miss) running audit must be reconciled to FAILED")
	}
	if !strings.Contains(w.Body.String(), "no process owns it") {
		t.Fatalf("client should receive the orphan notice for a true orphan: %q", w.Body.String())
	}
}
