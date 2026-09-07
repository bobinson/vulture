package agui

import (
	"encoding/json"

	"github.com/vulture/backend/internal/model"
)

// ParseSnapshotFindings extracts findings from an agent's `result` StateSnapshot
// payload, tolerating a malformed row the way ParseDeltaFindings does.
//
// WHY THIS EXISTS (feature 0082). The delta path has always been per-row
// tolerant: ParseDeltaFindings skips a row it cannot unmarshal and keeps the
// rest. The snapshot path was not — it unmarshalled the whole payload into
// []model.Finding and returned nothing on any error, so ONE finding carrying
// `"line_start": "55"` took the entire report to zero. That is a reachable
// state, not a hypothetical: VULTURE_LLM_COERCE_LINES exists precisely because
// a model answering with a string line number is otherwise "dropped in SILENCE
// by Go's LineStart int unmarshal", and it is a documented rollback switch.
//
// Behaviour change is strictly a recovery — a malformed row costs one row
// instead of all of them — so this ships with no feature switch.
//
// Returns the surviving findings and the count of rows that failed to parse.
// The caller is expected to log a non-zero malformed count; a silent drop is
// the failure mode this function was written to end.
func ParseSnapshotFindings(snapshot json.RawMessage, agentType string) ([]model.Finding, int) {
	// Parse the envelope loosely so an unparseable row cannot reach the
	// typed decode below. Findings stay raw for the per-row pass.
	var envelope struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if json.Unmarshal(snapshot, &envelope) != nil {
		return nil, 0
	}

	out := make([]model.Finding, 0, len(envelope.Findings))
	malformed := 0
	for _, raw := range envelope.Findings {
		var f model.Finding
		if json.Unmarshal(raw, &f) != nil {
			malformed++
			continue
		}
		if agentType != "" {
			f.AgentType = agentType
		}
		out = append(out, f)
	}
	return out, malformed
}

// ParseSnapshotScore reads the score off a result snapshot. Split from
// ParseSnapshotFindings so a malformed findings array cannot cost the score
// and vice versa.
func ParseSnapshotScore(snapshot json.RawMessage) (float64, bool) {
	var envelope struct {
		Score *float64 `json:"score"`
	}
	if json.Unmarshal(snapshot, &envelope) != nil || envelope.Score == nil {
		return 0, false
	}
	return *envelope.Score, true
}
