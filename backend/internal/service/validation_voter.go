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
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}

	// V7 amendment: authoritative-demoting check (a `# nosec` etc.)
	// alone lands the finding in `likely_fp` regardless of how many
	// other layers disagree.
	for _, c := range checks {
		if _, isAuth := AuthoritativeCheckIDs[c.ID]; isAuth && c.Weight < 0 {
			if confidence > 0.05 {
				confidence = 0.05
			}
			return VoteResult{Status: "likely_fp", Confidence: confidence}
		}
	}

	// V7: at least 2 demoting checks required for `likely_fp`.
	demotingCount := 0
	for _, c := range checks {
		if c.Weight < 0 {
			demotingCount++
		}
	}
	if confidence < 0.30 && demotingCount >= 2 {
		return VoteResult{Status: "likely_fp", Confidence: confidence}
	}
	if confidence < 0.55 {
		return VoteResult{Status: "suspicious", Confidence: confidence}
	}
	return VoteResult{Status: "high_confidence", Confidence: confidence}
}

// VoterCheck is the input shape Vote consumes.
type VoterCheck struct {
	ID     string
	Weight float64
}
