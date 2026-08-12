// Package service — validation_voter.go
//
// ╔══════════════════════════════════════════════════════════════╗
// ║  voter rules — PARITY-CRITICAL                              ║
// ║                                                              ║
// ║  If you modify this file, you MUST modify                    ║
// ║  agents/shared/shared/validate/voter.py in the same PR.     ║
// ║                                                              ║
// ║  Parity IS enforced: validation_voter_parity_test.go and     ║
// ║  test_voter_parity.py consume the same fixture,              ║
// ║  testdata/voter_parity_cases.json, and assert identical      ║
// ║  (status, confidence) for every case. Feature 0072 built it; ║
// ║  before that both headers described a test that did not      ║
// ║  exist, and the Python header claimed CI enforced it.        ║
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

// ── Feature 0072: obligations ────────────────────────────────────────────
// An obligation travels as its own check, carrying its state in `Result`.
// PARITY: these literals are duplicated in validate/voter.py and asserted by
// the shared fixture. If they drift, the gate silently disables — which is why
// the fixture pins the literal strings and not just the behaviour.
const (
	ObligationID         = "obligation"
	ObligationUnknown    = "unknown"
	ObligationDischarged = "discharged"
	ObligationRefuted    = "refuted"

	// A promoting llm_judge verdict carries its admissibility in Result,
	// decided at ingestion in the agent where the source is readable.
	JudgeCited   = "real_bug"
	JudgeUncited = "real_bug_uncited"
	// JudgeUndecided: the judge DECLINED to decide (exploitable == 0.5, the
	// prompt's own "cannot judge" value). Distinct from JudgeUncited, which is
	// "claimed a bug without citing". Inadmissible by CONSTRUCTION —
	// judgeVerdictAdmissible compares one literal, so anything != JudgeCited
	// already fails. Mirrors JUDGE_UNDECIDED in voter.py.
	JudgeUndecided = "undecided"
)

// AuthoritativePositiveIDs are check IDs whose POSITIVE weight is human ground
// truth and overrides the obligation gate. The weight test in
// hasAuthoritativePositive is load-bearing: `memory` is bidirectional, so
// keying on the id alone would let a user marking something a FALSE POSITIVE
// grant it a confirmation override.
var AuthoritativePositiveIDs = map[string]struct{}{
	"memory": {},
}

// ConfidenceCeilingUnverified — feature 0072 T4.2 (C2/AC5): confidence 1.0 is
// reserved. A single judge verdict at exploitable >= 0.834 used to clamp to
// exactly 1.000 — a model vote presenting as total certainty. The ceiling is
// the CLAMP BOUND, never an `if confidence >= 1.0` equality test: the two
// voters fold weights in different orders (accumulate-from-0.5 here,
// 0.5 + sum(w) in Python), so an equality trigger can fire in one language
// and not the other for the same checks (measured: weights {0.1, 0.3, 0.1}
// give 1.0 in Python and 0.9999999999999999 here).
//
// Only ground truth lifts the ceiling — today an operator's own positive
// label (AuthoritativePositiveIDs); a future mechanical-verification check
// id joins that set. PARITY: mirrored in voter.py; pinned by the fixture.
const ConfidenceCeilingUnverified = 0.99

// VoteResult is the output of Vote.
type VoteResult struct {
	Status     string
	Confidence float64
}

// clampConfidence clamps a raw weight-sum into the [0,hi] band.
func clampConfidence(v, hi float64) float64 {
	if v < 0 {
		return 0
	}
	if v > hi {
		return hi
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

// isRefuted reports whether the obligation was refuted at the class's declared
// scope. Mirrors _is_refuted in voter.py.
func isRefuted(checks []VoterCheck) bool {
	for _, c := range checks {
		if c.ID == ObligationID && c.Result == ObligationRefuted {
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

// hasAuthoritativePositive reports an operator's own POSITIVE label.
// Mirrors validate/voter.py::_has_authoritative_positive().
func hasAuthoritativePositive(checks []VoterCheck) bool {
	for _, c := range checks {
		if _, ok := AuthoritativePositiveIDs[c.ID]; ok && c.Weight > 0 {
			return true
		}
	}
	return false
}

// judgeVerdictAdmissible reports whether a promoting judge verdict cited
// something checkable. Fails closed: a verdict cached under an older schema
// carries neither marker. Mirrors validate/voter.py::_judge_verdict_admissible().
func judgeVerdictAdmissible(c VoterCheck) bool {
	return c.Result == JudgeCited
}

// solePromoterIsInadmissibleJudge reports that the ONLY thing raising this
// finding is a judge verdict citing nothing. Sign-aware by construction.
// Mirrors validate/voter.py::_sole_promoter_is_inadmissible_judge().
func solePromoterIsInadmissibleJudge(checks []VoterCheck) bool {
	var promoting []VoterCheck
	for _, c := range checks {
		if c.Weight > 0 {
			promoting = append(promoting, c)
		}
	}
	if len(promoting) != 1 {
		return false
	}
	only := promoting[0]
	return only.ID == "llm_judge" && !judgeVerdictAdmissible(only)
}

// mayConfirm reports whether this finding may carry the high_confidence LABEL.
// Mirrors validate/voter.py::_may_confirm().
func mayConfirm(checks []VoterCheck) bool {
	if hasAuthoritativePositive(checks) {
		return true
	}
	for _, c := range checks {
		if c.ID == ObligationID && c.Result == ObligationUnknown {
			return false
		}
	}
	return !solePromoterIsInadmissibleJudge(checks)
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
	ceiling := ConfidenceCeilingUnverified
	if hasAuthoritativePositive(checks) {
		ceiling = 1.0
	}
	confidence = clampConfidence(confidence, ceiling)
	if hasAuthoritativeDemotion(checks) {
		if confidence > 0.05 {
			confidence = 0.05
		}
		return VoteResult{Status: "likely_fp", Confidence: confidence}
	}
	// Feature 0072: a REFUTED obligation is positive evidence of absence, not an
	// absence of evidence — the mitigation was found at the class's declared
	// scope. It is the only verdict that REMOVES a finding rather than merely
	// withholding its label, and reaching it requires STRUCTURAL evidence
	// (MAX_VERDICT in refutation.py), so a textual match can never get here.
	//
	// Confidence is preserved: it measures how strong the DETECTION evidence is,
	// and the obligation is a separate axis. Collapsing the two would make a
	// refuted finding indistinguishable from a weak one, and reviewing refuted
	// findings by detection strength is how the refuter itself gets audited.
	if isRefuted(checks) {
		return VoteResult{Status: "likely_fp", Confidence: confidence}
	}
	status := classify(confidence, countDemoting(checks))
	// Withhold the LABEL, never the number. A blocking obligation
	// deliberately does not prevent likely_fp — independent refutation may still
	// dismiss a finding whose obligations were never searched.
	if status == "high_confidence" && !mayConfirm(checks) {
		status = "suspicious"
	}
	return VoteResult{Status: status, Confidence: confidence}
}

// VoterCheck is the input shape Vote consumes.
//
// Result was added by feature 0072. Before it, both re-vote sites in
// stream_handler.go rebuilt checks from id+weight ONLY and recomputed
// confidence from scratch, so any semantics not expressible as a weight was
// erased the moment L3 or L4 fired. An obligation would have been invisible to
// the backend and the first cross-agent match would have promoted a gated
// finding straight back.
type VoterCheck struct {
	ID     string
	Weight float64
	Result string
}
