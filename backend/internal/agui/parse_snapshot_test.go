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
		"empty findings array":  {`{"findings":[]}`, 0},
		"every row malformed":   {`{"findings":[{"line_start":"x"},{"line_end":"y"}]}`, 0},
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

// Feature 0091 — the scope/evidence half of the result event.

// TestParseScanOutcomeFullPayload reads a payload from a 0091-capable agent.
func TestParseScanOutcomeFullPayload(t *testing.T) {
	in := `{
		"result_schema": 2,
		"pruned_dirs": [".vscode", "node_modules"],
		"lineage_checks": [
			{"lineage_id":"l-1","outcome":"confirmed","reason":"exact","line_start":7,"line_end":7,"file_hash":"sha256:aa"},
			{"lineage_id":"l-2","outcome":"gone","reason":"absent","file_hash":"sha256:bb"}
		],
		"findings": [{"title":"x"}],
		"score": 71
	}`
	got := ParseScanOutcome(json.RawMessage(in))
	if got.ResultSchema != 2 {
		t.Fatalf("result_schema = %d, want 2", got.ResultSchema)
	}
	if !got.HasEvidenceProtocol() {
		t.Fatal("schema 2 must read as evidence-capable")
	}
	if len(got.PrunedDirs) != 2 || got.PrunedDirs[0] != ".vscode" {
		t.Fatalf("pruned_dirs = %v", got.PrunedDirs)
	}
	if len(got.LineageChecks) != 2 {
		t.Fatalf("lineage_checks = %d rows, want 2", len(got.LineageChecks))
	}
	c := got.LineageChecks[0]
	if c.LineageID != "l-1" || c.Outcome != "confirmed" || c.Reason != "exact" ||
		c.LineStart != 7 || c.LineEnd != 7 || c.FileHash != "sha256:aa" {
		t.Fatalf("check 0 round-tripped wrong: %+v", c)
	}
}

// TestParseScanOutcomeOldAgent is the case the whole version gate exists for:
// a payload with no `result_schema` must yield 0, NOT be normalised up to the
// current schema. Reading "absent" as "schema 2, nothing pruned" would grant
// every pre-0091 agent in the fleet the right to close LLM-tier rows on
// silence — exactly the defect (S26).
func TestParseScanOutcomeOldAgent(t *testing.T) {
	for name, in := range map[string]string{
		"pre-0091 payload":  `{"findings":[{"title":"x"}],"score":71}`,
		"empty object":      `{}`,
		"empty bytes":       ``,
		"unparseable":       `not json`,
		"explicit schema 1": `{"result_schema":1,"findings":[]}`,
		"array, not object": `[1,2,3]`,
	} {
		t.Run(name, func(t *testing.T) {
			got := ParseScanOutcome(json.RawMessage(in))
			if got == nil {
				t.Fatal("ParseScanOutcome must never return nil")
			}
			if got.HasEvidenceProtocol() {
				t.Fatalf("%q must read as an OLD agent, got schema %d", in, got.ResultSchema)
			}
			if len(got.LineageChecks) != 0 || len(got.PrunedDirs) != 0 {
				t.Fatalf("old agent must yield no scope and no evidence: %+v", got)
			}
		})
	}
}

// TestParseScanOutcomeIsIndependentOfFindings pins the envelope split: a
// findings array that cannot be decoded must not cost the scope/evidence keys,
// and vice versa. Both are read from the same bytes by separate parsers
// precisely so one malformed half cannot take the other down.
func TestParseScanOutcomeIsIndependentOfFindings(t *testing.T) {
	in := json.RawMessage(`{"result_schema":2,"pruned_dirs":["a"],
		"lineage_checks":[{"lineage_id":"l-1","outcome":"gone"}],
		"findings":[{"line_start":"55"},{"title":"good","file_path":"f.go"}]}`)

	outcome := ParseScanOutcome(in)
	if !outcome.HasEvidenceProtocol() || len(outcome.LineageChecks) != 1 {
		t.Fatalf("a malformed finding row cost the evidence keys: %+v", outcome)
	}
	findings, malformed := ParseSnapshotFindings(in, "cwe")
	if len(findings) != 1 || malformed != 1 {
		t.Fatalf("findings parse changed: %d rows, %d malformed", len(findings), malformed)
	}
}

// TestParseScanOutcomeDegradedAndTruncated pins the two "the scan did not see
// everything" flags, each of which suppresses a different closure.
func TestParseScanOutcomeDegradedAndTruncated(t *testing.T) {
	got := ParseScanOutcome(json.RawMessage(
		`{"result_schema":2,"degraded_reason":"llm phase failed","scan_truncated":true}`))
	if got.DegradedReason != "llm phase failed" {
		t.Fatalf("degraded_reason = %q", got.DegradedReason)
	}
	if !got.ScanTruncated {
		t.Fatal("scan_truncated must survive the parse")
	}
}
