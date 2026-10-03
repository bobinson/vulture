package agui

import (
	"encoding/json"

	"github.com/vulture/backend/internal/model"
)

// agentFindingWire shadows the keys an agent must not be able to set. The
// outer field wins encoding/json's name resolution over the embedded one, so
// the agent's value lands in a RawMessage that is never read.
type agentFindingWire struct {
	model.Finding
	// Feature 0096: labels are applied by the backend alone, from a mapping
	// validated per §3.4. Decoding the agent's value into the typed field
	// would both let any agent self-label past that validation and turn a
	// value of the wrong shape into a dropped finding — before 0096 the key
	// was unknown to the struct and cost nothing.
	ComplianceLabels json.RawMessage `json:"compliance_labels"`
}

// DecodeAgentFinding is the one decode of a finding object an agent sent, used
// by every ingest path (result snapshot, read-only delta tap, persisted delta)
// so none can admit a backend-only field the others refuse. It reports false
// exactly when the row is malformed, as json.Unmarshal would.
func DecodeAgentFinding(raw json.RawMessage) (model.Finding, bool) {
	var w agentFindingWire
	if json.Unmarshal(raw, &w) != nil {
		return model.Finding{}, false
	}
	return w.Finding, true
}
