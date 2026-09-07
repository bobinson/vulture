package service

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// ---------- fixtures ----------

func deltaEvent(agent string, fs ...model.Finding) *model.AgUIEvent {
	patches := make([]map[string]interface{}, 0, len(fs))
	for _, f := range fs {
		b, _ := json.Marshal(f)
		patches = append(patches, map[string]interface{}{
			"op": "add", "path": "/findings/-", "value": json.RawMessage(b),
		})
	}
	raw, _ := json.Marshal(patches)
	return &model.AgUIEvent{Type: model.EventStateDelta, AgentType: agent, Delta: raw}
}

func snapshotEvent(agent string, rawRows ...string) *model.AgUIEvent {
	body := "{\"score\":72,\"findings\":["
	for i, r := range rawRows {
		if i > 0 {
			body += ","
		}
		body += r
	}
	body += "]}"
	return &model.AgUIEvent{
		Type: model.EventStateSnapshot, AgentType: agent,
		Snapshot: json.RawMessage(body),
	}
}

func row(id, path, cat string, line int, status string) string {
	return fmt.Sprintf(
		`{"id":%q,"file_path":%q,"category":%q,"line_start":%d,"title":"t-%s",`+
			`"validation_status":%q,"validation_confidence":0.05,`+
			`"validation":{"status":%q,"confidence":0.05,"checks":[{"name":"anchor","weight":-1.0}]}}`,
		id, path, cat, line, id, status, status)
}

// The C1 collision, verbatim: a rollup parent whose line_start EQUALS its
// lowest-line member's, same file, same category. Distinguished only by id.
const (
	childRow  = `{"id":"child-1","file_path":"routes/address.ts","category":"CWE-20","line_start":11,"title":"member","validation_status":"high_confidence"}`
	parentRow = `{"id":"rollup-abc","is_rollup":true,"file_path":"routes/address.ts","category":"CWE-20","line_start":11,"title":"member","instance_count":7,"provenance":"catalog_rollup"}`
)

func feed(t *testing.T, tap *cweTap, evs ...*model.AgUIEvent) {
	t.Helper()
	for _, e := range evs {
		tap.observe(e)
	}
}

// ---------- T-LOSS ----------

func TestTapIsLossless(t *testing.T) {
	tap := &cweTap{}
	feed(t, tap,
		deltaEvent("cwe",
			model.Finding{ID: "child-1", FilePath: "routes/address.ts", Category: "CWE-20", LineStart: 11, Title: "member"},
			model.Finding{ID: "solo-2", FilePath: "b.ts", Category: "CWE-89", LineStart: 4, Title: "solo"},
		),
		snapshotEvent("cwe", childRow, parentRow, row("solo-2", "b.ts", "CWE-89", 4, "likely_fp")),
	)

	got, _ := tap.snapshot()
	// NON-VACUITY: the fixture must really contain both halves of the collision.
	if len(got) == 0 {
		t.Fatal("non-vacuity: tap produced nothing")
	}

	ids := map[string]bool{}
	for _, f := range got {
		ids[f.ID] = true
	}
	for _, want := range []string{"child-1", "rollup-abc", "solo-2"} {
		if !ids[want] {
			t.Errorf("id %q lost by the tap — parent and its min-line child are DISTINCT rows", want)
		}
	}
	if len(got) != 3 {
		t.Errorf("want 3 rows, got %d: %v", len(got), ids)
	}
}

// ---------- T-MALFORMED (C2, C3) ----------

func TestSnapshotPartialParse(t *testing.T) {

	t.Run("one bad row costs one row, not the batch", func(t *testing.T) {
		tap := &cweTap{}
		feed(t, tap, snapshotEvent("cwe",
			row("g1", "a.ts", "CWE-79", 10, "suspicious"),
			`{"id":"bad","file_path":"b.ts","category":"CWE-89","line_start":"55","title":"bad"}`,
			row("g2", "c.ts", "CWE-22", 30, "high_confidence"),
		))
		got, status := tap.snapshot()
		if len(got) != 2 {
			t.Errorf("want 2 surviving rows, got %d", len(got))
		}
		if !status {
			t.Error("a snapshot with parseable rows must count as a finished report")
		}
	})

	t.Run("every row malformed is NOT a finished report", func(t *testing.T) {
		tap := &cweTap{}
		feed(t, tap,
			deltaEvent("cwe", model.Finding{ID: "d1", FilePath: "a.ts", Category: "CWE-79", LineStart: 1, Title: "d"}),
			snapshotEvent("cwe", `{"line_start":"x","category":"CWE-1"}`, `{"line_end":"y","category":"CWE-2"}`),
		)
		got, status := tap.snapshot()
		if status {
			t.Error("zero parseable rows must not report the CWE stage completed")
		}
		if len(got) != 1 || got[0].ID != "d1" {
			t.Errorf("fallback to deltas failed: %+v", got)
		}
	})

	// CORRECTED. This case first asserted that an empty report is "not
	// finished". That was wrong, and TestStream_OwaspReceivesCweFindingsAsPriors
	// — the older contract — caught it: an agent scanning a genuinely CLEAN
	// repository sends a valid report with an empty findings array, and calling
	// that a failed stage would misreport every clean scan. "Did the agent
	// finish" and "did it find anything" are different questions. The confusion
	// the rule exists to prevent is the UNINTELLIGIBLE report (case B), not the
	// empty one.
	t.Run("an empty report IS finished, and still falls back to deltas", func(t *testing.T) {
		tap := &cweTap{}
		feed(t, tap,
			deltaEvent("cwe", model.Finding{ID: "d1", FilePath: "a.ts", Category: "CWE-79", LineStart: 1, Title: "d"}),
			snapshotEvent("cwe"),
		)
		got, status := tap.snapshot()
		if !status {
			t.Error("a valid empty report means the agent finished with zero findings, not that it failed")
		}
		// It still falls back, so a report that disagrees with the stream never
		// costs findings the stream already carried.
		if len(got) != 1 || got[0].ID != "d1" {
			t.Errorf("want the delta fallback, got %+v", got)
		}
	})

	t.Run("a clean agent reports finished and contributes nothing", func(t *testing.T) {
		tap := &cweTap{}
		feed(t, tap, snapshotEvent("cwe"))
		got, status := tap.snapshot()
		if !status {
			t.Error("a clean scan must report completed")
		}
		if len(got) != 0 {
			t.Errorf("a clean agent must contribute no priors, got %d", len(got))
		}
	})
}

// ---------- T-XSS-SYMMETRY (C5) ----------

func TestForeignAgentCweRowsAreFilteredSymmetrically(t *testing.T) {
	tap := &cweTap{}
	feed(t, tap,
		deltaEvent("xss", model.Finding{ID: "x1", FilePath: "h.ts", Category: "CWE-79", LineStart: 5, Title: "dom xss"}),
		snapshotEvent("xss", row("x1", "h.ts", "CWE-79", 5, "high_confidence")),
	)

	got, _ := tap.snapshot()
	if len(got) == 0 {
		t.Fatal("non-vacuity: xss emits CWE-categorised rows and must be tapped")
	}
	// The xss agent DID send a snapshot, so its snapshot rows win — exactly as
	// they would for the cwe agent. Before 0082 the delta branch accepted any
	// agent while the snapshot branch accepted only "cwe", so an xss row could
	// never be superseded by its own report.
	if got[0].ValidationStatus != "high_confidence" {
		t.Errorf("xss snapshot row not consumed; got status %q from the delta row instead", got[0].ValidationStatus)
	}
}

// ---------- verdict transport (C4) ----------

func TestPriorsCarryTheValidationBlob(t *testing.T) {
	tap := &cweTap{}
	feed(t, tap, snapshotEvent("cwe", row("s1", "a.ts", "CWE-79", 1, "likely_fp")))
	fs, _ := tap.snapshot()
	if len(fs) == 0 {
		t.Fatal("non-vacuity: no rows tapped")
	}
	priors := findingsToPriors(fs)
	if priors[0].ValidationStatus != "likely_fp" {
		t.Errorf("status not carried: %q", priors[0].ValidationStatus)
	}
	if priors[0].Validation == nil {
		t.Fatal("the validation BLOB is not carried — the backend will synthesise one and re-vote from 0.5")
	}
	if priors[0].Validation["status"] != "likely_fp" {
		t.Errorf("blob status wrong: %v", priors[0].Validation["status"])
	}
}
