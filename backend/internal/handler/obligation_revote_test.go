package handler

import (
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0072 G1. The obligation's state and a judge verdict's admissibility
// both live in a check's `result` field. The Go re-vote sites rebuild
// service.VoterCheck by hand from the serialised map, so dropping `result`
// there would silently erase the gate on the first L3/L4 re-vote — while the
// agent that applied it still reported the gated status. Nothing else in the
// system would notice, which is why this seam is tested directly.

func obligationCheck(state string) map[string]interface{} {
	return map[string]interface{}{
		"id": "obligation", "result": state, "weight": 0.0,
		"reason": "test obligation",
	}
}

func promotingCheck() map[string]interface{} {
	return map[string]interface{}{
		"id": "path", "result": "promoted", "weight": 0.10,
		"reason": "production path",
	}
}

func findingWith(checks ...map[string]interface{}) model.Finding {
	raw := make([]interface{}, 0, len(checks))
	for _, c := range checks {
		raw = append(raw, c)
	}
	return model.Finding{
		CrossAgentOrigins: []string{"owasp"},
		Validation: map[string]interface{}{
			"status": "suspicious", "confidence": 0.5, "checks": raw,
		},
	}
}

func TestCrossAgentRevotePreservesARefutedDismissal(t *testing.T) {
	// A cross-agent confirmation ADDS weight. Without `result` surviving the
	// rebuild the finding would be promoted out of likely_fp by corroboration
	// of a finding already shown to be mitigated.
	got := applyCrossAgentValidation(findingWith(
		promotingCheck(), obligationCheck("refuted")))

	if got.ValidationStatus != "likely_fp" {
		t.Fatalf("refuted obligation lost across re-vote: status=%q confidence=%v",
			got.ValidationStatus, got.ValidationConfidence)
	}
}

func TestCrossAgentRevotePreservesAnUnknownBlock(t *testing.T) {
	got := applyCrossAgentValidation(findingWith(
		promotingCheck(), obligationCheck("unknown")))

	if got.ValidationStatus == "high_confidence" {
		t.Fatalf("unknown obligation stopped blocking across re-vote: status=%q",
			got.ValidationStatus)
	}
}

func TestCrossAgentRevoteStillConfirmsWhenDischarged(t *testing.T) {
	// The control: the gate must not be blocking everything unconditionally,
	// or the two tests above would pass for the wrong reason.
	got := applyCrossAgentValidation(findingWith(
		promotingCheck(), obligationCheck("discharged")))

	if got.ValidationStatus != "high_confidence" {
		t.Fatalf("discharged obligation should permit confirmation, got %q",
			got.ValidationStatus)
	}
}
