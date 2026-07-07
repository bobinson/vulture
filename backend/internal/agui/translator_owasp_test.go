package agui

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestTranslateResult_PreservesOwaspCoverage proves the OWASP coverage
// manifest survives result translation (feature 0063): translateResult emits
// a StateSnapshot carrying the full result payload verbatim, so the frontend
// can read owasp_coverage off the live stream.
func TestTranslateResult_PreservesOwaspCoverage(t *testing.T) {
	data := json.RawMessage(`{"findings":[],"score":100,"summary":"s","owasp_coverage":{"edition":"2021","cwe_stage_status":"completed","categories":[]}}`)
	evs, err := translateResult("owasp", data)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		if len(e.Snapshot) > 0 && strings.Contains(string(e.Snapshot), "owasp_coverage") {
			found = true
		}
	}
	if !found {
		t.Fatal("owasp_coverage dropped during result translation")
	}
}
