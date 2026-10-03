package handler

import (
	"encoding/json"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0096: the persistence-side delta path must treat an agent's
// `compliance_labels` exactly as the read-only parsers do — keep the finding,
// drop the value. Labels are backend-applied from a validated mapping only.
func TestExtractDeltaFindings_AgentComplianceLabelsAreDroppedNotFatal(t *testing.T) {
	shapes := map[string]string{
		"string":         `"A07"`,
		"lineage object": `{"owasp:2025":["A07"]}`,
		"self-labelled":  `[{"framework":"owasp","edition":"2025","category_id":"A99","cwe":"CWE-1"}]`,
	}
	for name, labels := range shapes {
		t.Run(name, func(t *testing.T) {
			delta := json.RawMessage(`[{"op":"add","path":"/findings/-","value":{"title":"t","severity":"high",` +
				`"category":"CWE-798","file_path":"a.go","compliance_labels":` + labels + `}}]`)
			var findings []model.Finding
			extractDeltaFindings(delta, "audit-0096", "chaos", &findings)
			if len(findings) != 1 {
				t.Fatalf("finding must be kept, got %d", len(findings))
			}
			if findings[0].ComplianceLabels != nil {
				t.Errorf("agent-supplied labels must not survive ingest, got %+v", findings[0].ComplianceLabels)
			}
			if findings[0].Fingerprint == "" || findings[0].AgentType != "chaos" {
				t.Errorf("the finding must be stamped as before: %+v", findings[0])
			}
		})
	}
}
