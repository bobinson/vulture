package agui

import (
	"encoding/json"
	"testing"
)

// T-PARSER-DRY: a snapshot with one malformed row must cost ONE row, not the
// whole batch. handler.parseSnapshot today unmarshals the entire payload into
// []model.Finding and returns nothing on any error, so a single
// `"line_start": "55"` takes every finding in the report to zero — silently.
// VULTURE_LLM_COERCE_LINES is a documented rollback switch that re-arms exactly
// that shape, so this is a reachable state, not a hypothetical one.
func TestParseSnapshotFindingsIsPerRowTolerant(t *testing.T) {
	payload := json.RawMessage(`{"score":72.5,"findings":[
		{"title":"good one","file_path":"a.ts","line_start":10,"category":"CWE-79"},
		{"title":"bad one","file_path":"b.ts","line_start":"55","category":"CWE-89"},
		{"title":"good two","file_path":"c.ts","line_start":30,"category":"CWE-22"}
	]}`)

	// NON-VACUITY: the fixture must really carry 3 rows, exactly 1 malformed.
	var probe struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		t.Fatalf("fixture itself is unparseable: %v", err)
	}
	if len(probe.Findings) != 3 {
		t.Fatalf("non-vacuity: fixture must hold 3 rows, got %d", len(probe.Findings))
	}

	got, malformed := ParseSnapshotFindings(payload, "cwe")
	if len(got) != 2 {
		t.Errorf("want 2 surviving rows, got %d — a malformed row must not take the batch", len(got))
	}
	if malformed != 1 {
		t.Errorf("want malformed=1, got %d — the drop must be counted, never silent", malformed)
	}
	for _, f := range got {
		if f.AgentType != "cwe" {
			t.Errorf("agentType not stamped on %q", f.Title)
		}
	}
}

func TestParseSnapshotFindingsEmptyAndBroken(t *testing.T) {
	for name, tc := range map[string]struct {
		in       string
		wantRows int
	}{
		"empty findings array": {`{"findings":[]}`, 0},
		"every row malformed":  {`{"findings":[{"line_start":"x"},{"line_end":"y"}]}`, 0},
		"payload not an object": {`[1,2,3]`, 0},
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := ParseSnapshotFindings(json.RawMessage(tc.in), "cwe")
			if len(got) != tc.wantRows {
				t.Errorf("want %d rows, got %d", tc.wantRows, len(got))
			}
		})
	}
}
