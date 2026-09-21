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

// ParseScanOutcome reads the feature-0091 scope and evidence keys off a
// `result` StateSnapshot: `result_schema`, `pruned_dirs`, `lineage_checks`,
// plus `degraded_reason` and `scan_truncated`.
//
// It deliberately does NOT re-parse findings. Findings keep their own per-row
// tolerant path (ParseSnapshotFindings) because ONE malformed finding must
// cost one finding, not the report — and by the same argument one malformed
// lineage check must not be able to cost the findings. The two live in
// separate envelopes so neither can take the other down, which is the same
// split ParseSnapshotScore already makes for the score.
//
// The whole payload is optional and every field is absent on a pre-0091 agent.
// An unparseable snapshot, or one with no `result_schema`, yields a zero
// ResultSchema — and that value is load-bearing rather than a default: it is
// what tells the closure pass that scope is UNKNOWN, so the scan may perform
// no LLM-tier and no pruned-dir closures (S26). Reading "absent" as "schema 2
// with nothing pruned" would silently restore the defect for every old agent
// in the fleet.
//
// translateResult forwards the result payload verbatim as the snapshot, so
// this reads exactly the bytes the agent sent; there is no parallel parser and
// no second transport.
func ParseScanOutcome(snapshot json.RawMessage) *model.ScanResult {
	out := &model.ScanResult{}
	if len(snapshot) == 0 {
		return out
	}
	var envelope struct {
		ResultSchema   int                  `json:"result_schema"`
		PrunedDirs     []string             `json:"pruned_dirs"`
		LineageChecks  []model.LineageCheck `json:"lineage_checks"`
		DegradedReason string               `json:"degraded_reason"`
		ScanTruncated  bool                 `json:"scan_truncated"`
	}
	if json.Unmarshal(snapshot, &envelope) != nil {
		return out
	}
	out.ResultSchema = envelope.ResultSchema
	out.PrunedDirs = envelope.PrunedDirs
	out.LineageChecks = envelope.LineageChecks
	out.DegradedReason = envelope.DegradedReason
	out.ScanTruncated = envelope.ScanTruncated
	return out
}
