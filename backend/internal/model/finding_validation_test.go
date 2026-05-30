package model

import (
	"encoding/json"
	"testing"
)

func TestFindingValidationDecode(t *testing.T) {
	payload := []byte(`{
		"id": "f1", "agent_type": "cwe", "severity": "high",
		"category": "CWE-89", "title": "SQL",
		"file_path": "/x.py", "line_start": 10, "line_end": 10,
		"validation_status": "suspicious",
		"validation_confidence": 0.5,
		"validation": {"status": "suspicious", "checks": []},
		"is_rollup": false,
		"instance_count": 1
	}`)
	var f Finding
	if err := json.Unmarshal(payload, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.ValidationStatus != "suspicious" {
		t.Errorf("status: got %q want suspicious", f.ValidationStatus)
	}
	if f.ValidationConfidence != 0.5 {
		t.Errorf("confidence: got %v want 0.5", f.ValidationConfidence)
	}
	if len(f.Validation) == 0 {
		t.Errorf("validation map empty: %v", f.Validation)
	}
}
