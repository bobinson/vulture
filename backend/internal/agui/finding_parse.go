package agui

import (
	"encoding/json"

	"github.com/vulture/backend/internal/model"
)

// ParseDeltaFindings extracts findings from a StateDelta patch produced by
// translateFinding, i.e. JSON-Patch `add` ops at path "/findings/-" whose
// value is a finding object.
//
// This is a READ-ONLY parse: unlike the stream handler's persistence path, it
// does not assign ids, fingerprints, or apply validation-replace ops. It is
// used by read-only consumers that need to observe findings mid-stream (e.g.
// the OWASP-over-CWE deferred mapping tap, feature 0063). agentType is
// stamped onto each parsed finding.
func ParseDeltaFindings(delta json.RawMessage, agentType string) []model.Finding {
	var patches []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	}
	if json.Unmarshal(delta, &patches) != nil {
		return nil
	}
	var out []model.Finding
	for _, p := range patches {
		if p.Op != "add" || p.Path != "/findings/-" {
			continue
		}
		var f model.Finding
		if json.Unmarshal(p.Value, &f) != nil {
			continue
		}
		if agentType != "" {
			f.AgentType = agentType
		}
		out = append(out, f)
	}
	return out
}
