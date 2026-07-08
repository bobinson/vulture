package agui

import (
	"encoding/json"
	"testing"
)

func TestParseDeltaFindings_ExtractsFields(t *testing.T) {
	delta := json.RawMessage(`[{"op":"add","path":"/findings/-","value":{"category":"CWE-89","title":"SQLi","severity":"critical","file_path":"a.py","line_start":3,"line_end":4,"check_id":"cwe.injection.sql"}}]`)
	got := ParseDeltaFindings(delta, "cwe")
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Category != "CWE-89" || f.LineStart != 3 || f.LineEnd != 4 || f.AgentType != "cwe" {
		t.Fatalf("bad parse: %+v", f)
	}
}

func TestParseDeltaFindings_IgnoresNonAddOps(t *testing.T) {
	delta := json.RawMessage(`[{"op":"replace","path":"/findings/0","value":{"category":"CWE-1"}}]`)
	if got := ParseDeltaFindings(delta, "cwe"); len(got) != 0 {
		t.Fatalf("expected 0 findings from replace op, got %d", len(got))
	}
}

func TestParseDeltaFindings_ToleratesGarbage(t *testing.T) {
	if got := ParseDeltaFindings(json.RawMessage(`not json`), "cwe"); got != nil {
		t.Fatalf("expected nil on garbage, got %+v", got)
	}
}
