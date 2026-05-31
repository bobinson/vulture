// Package service — validation_voter.go
//
// ╔══════════════════════════════════════════════════════════════╗
// ║  voter rules — PARITY-CRITICAL                              ║
// ║                                                              ║
// ║  If you modify this file, you MUST modify                    ║
// ║  agents/shared/shared/validate/voter.py in the same PR.     ║
// ║  The cross-language parity is currently enforced by code     ║
// ║  review; a formal JSON-fixture parity test is on the         ║
// ║  follow-up list (feature 0045 §H).                          ║
// ║                                                              ║
// ║  Considered alternatives: codegen (heavy), subprocess call   ║
// ║  to Python from Go (latency) — rejected for v1.              ║
// ╚══════════════════════════════════════════════════════════════╝

package service

// AuthoritativeCheckIDs are check IDs that can demote a finding to
// `likely_fp` solo, bypassing the ≥2-demoting-checks floor of V7.
// In v1 the only authoritative check is `suppression` (an explicit
// `# nosec` / `gosec:ignore` etc. is the operator's own decision).
var AuthoritativeCheckIDs = map[string]struct{}{
	"suppression": {},
}

// VoteResult is the output of Vote.
type VoteResult struct {
	Status     string
	Confidence float64
}

// clampConfidence clamps a raw weight-sum into the [0,1] band.
func clampConfidence(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// hasAuthoritativeDemotion reports whether any check in
// AuthoritativeCheckIDs has a negative weight — operator overrides
// like `# nosec` carry singular weight in the V7 vote.
func hasAuthoritativeDemotion(checks []VoterCheck) bool {
	for _, c := range checks {
		if _, isAuth := AuthoritativeCheckIDs[c.ID]; isAuth && c.Weight < 0 {
			return true
		}
	}
	return false
}

// countDemoting returns the number of negative-weight checks.
func countDemoting(checks []VoterCheck) int {
	n := 0
	for _, c := range checks {
		if c.Weight < 0 {
			n++
		}
	}
	return n
}

// classify maps (clamped confidence, demoting count) → status.
// Mirrors validate/voter.py::_classify().
func classify(confidence float64, demotingCount int) string {
	if confidence < 0.30 && demotingCount >= 2 {
		return "likely_fp"
	}
	if confidence < 0.55 {
		return "suspicious"
	}
	return "high_confidence"
}

// Vote applies the V7 rules to a list of check weights and ids.
// Mirrors `agents/shared/shared/validate/voter.py::vote()` exactly.
//
// `checks` is the per-finding slice of (id, weight) pairs. Weights
// outside [-1, +1] are tolerated; confidence is clamped to [0, 1].
func Vote(checks []VoterCheck) VoteResult {
	confidence := 0.5
	for _, c := range checks {
		confidence += c.Weight
	}
	confidence = clampConfidence(confidence)
	if hasAuthoritativeDemotion(checks) {
		if confidence > 0.05 {
			confidence = 0.05
		}
		return VoteResult{Status: "likely_fp", Confidence: confidence}
	}
	return VoteResult{
		Status:     classify(confidence, countDemoting(checks)),
		Confidence: confidence,
	}
}

// VoterCheck is the input shape Vote consumes.
type VoterCheck struct {
	ID     string
	Weight float64
}
