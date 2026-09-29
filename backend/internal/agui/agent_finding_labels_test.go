package agui

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Feature 0096: compliance labels are written by the backend alone, from a
// validated mapping (§3.4). An agent payload that carries `compliance_labels`
// is untrusted input on a key the finding struct now owns, so every agent
// decode path must (a) keep the finding whatever shape the key has — before
// 0096 it was an unknown key and cost nothing — and (b) drop the value, so no
// agent can self-label past validation.
var agentLabelShapes = map[string]string{
	"string":         `"A07"`,
	"lineage object": `{"owasp:2025":["A07"]}`,
	"self-labelled":  `[{"framework":"owasp","edition":"2025","category_id":"A99","category_name":"made up","cwe":"CWE-1"}]`,
	"null":           `null`,
}

func labelledFindingJSON(labels string) string {
	return fmt.Sprintf(`{"title":"t","severity":"high","category":"CWE-798","file_path":"a.go","compliance_labels":%s}`, labels)
}

func TestParseSnapshotFindings_AgentComplianceLabelsAreDroppedNotFatal(t *testing.T) {
	for name, labels := range agentLabelShapes {
		t.Run(name, func(t *testing.T) {
			snapshot := json.RawMessage(`{"findings":[` + labelledFindingJSON(labels) + `]}`)
			got, malformed := ParseSnapshotFindings(snapshot, "chaos")
			if malformed != 0 || len(got) != 1 {
				t.Fatalf("finding must be kept: got %d, malformed %d", len(got), malformed)
			}
			if got[0].ComplianceLabels != nil {
				t.Errorf("agent-supplied labels must not survive ingest, got %+v", got[0].ComplianceLabels)
			}
			if got[0].Category != "CWE-798" || got[0].Title != "t" {
				t.Errorf("the rest of the finding must decode as before: %+v", got[0])
			}
		})
	}
}

func TestParseDeltaFindings_AgentComplianceLabelsAreDroppedNotFatal(t *testing.T) {
	for name, labels := range agentLabelShapes {
		t.Run(name, func(t *testing.T) {
			delta := json.RawMessage(`[{"op":"add","path":"/findings/-","value":` + labelledFindingJSON(labels) + `}]`)
			got := ParseDeltaFindings(delta, "chaos")
			if len(got) != 1 {
				t.Fatalf("finding must be kept, got %d", len(got))
			}
			if got[0].ComplianceLabels != nil {
				t.Errorf("agent-supplied labels must not survive ingest, got %+v", got[0].ComplianceLabels)
			}
		})
	}
}

func TestDecodeAgentFinding_StillRejectsAMalformedFinding(t *testing.T) {
	if _, ok := DecodeAgentFinding(json.RawMessage(`{"line_start":"55"}`)); ok {
		t.Fatal("shadowing compliance_labels must not make every other field tolerant")
	}
}
