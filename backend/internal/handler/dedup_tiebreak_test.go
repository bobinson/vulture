package handler

import (
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0079 D1 / Phase 0: comparator soundness, BEFORE any key change.
//
// Every key change in this feature manufactures collisions that do not exist
// today. Today's arbiter resolves an equal-score collision by ARRIVAL ORDER
// (crossAgentPrefers ends `return challengerScore > incumbentScore`, false on a
// tie, so first-seen keeps the key) and arrival order is the interleaving of
// concurrent agent goroutines into one channel. That makes the winner a coin
// flip, and it is measurable: helpers.ts:138 flipped 4-2 across six runs of the
// same image between two xss rows scoring 53-53.
//
// So a total, transitive tie-break must land FIRST, or every new collision the
// later phases create is decided nondeterministically.
//
// It is a COMPARATOR change, not a sort. The reviewed design's sort-plus-second-
// pass measured 2.6x the 33.4ms/50k-finding baseline; a tie-break in the
// existing comparison costs zero extra passes.

func fx(id, agent, title, path string, line int, sev model.Severity) model.Finding {
	return model.Finding{ID: id, AgentType: agent, Title: title, FilePath: path,
		LineStart: line, Severity: sev}
}

// D1-T1 — NON-VACUITY. The tie-break is only reachable if equal-score
// collisions actually occur. Assert the condition exists before asserting the
// behaviour, or this whole file is a green test over an impossible state.
func TestEqualScoreCollisionsAreReachable(t *testing.T) {
	a := fx("a", "xss", "Stored XSS via database content", "h.ts", 138, model.SeverityCritical)
	b := fx("b", "xss", "Reflected XSS via innerHTML", "h.ts", 138, model.SeverityCritical)
	a.CodeSnippet, b.CodeSnippet = "x", "y"
	if findingDetailScore(a) != findingDetailScore(b) {
		t.Fatalf("the measured 53-53 tie is not reproducible here (%d vs %d); "+
			"the tie-break below would be unreachable",
			findingDetailScore(a), findingDetailScore(b))
	}
}

// D1-T2 — TOTALITY. For any two distinct findings exactly one ordering holds.
// Without this, "prefers" can be true both ways and the winner depends on which
// row happened to be the incumbent.
func TestTieBreakIsTotal(t *testing.T) {
	a := fx("a", "xss", "Alpha", "h.ts", 138, model.SeverityCritical)
	b := fx("b", "xss", "Beta", "h.ts", 138, model.SeverityCritical)
	sa, sb := findingDetailScore(a), findingDetailScore(b)

	ab := crossAgentPrefers(a, b, sa, sb, true)
	ba := crossAgentPrefers(b, a, sb, sa, true)
	if ab == ba {
		t.Fatalf("not total: prefers(a,b)=%v and prefers(b,a)=%v — the winner "+
			"depends on arrival order, which is exactly the coin flip", ab, ba)
	}
}

// D1-T3 — TRANSITIVITY. Measured today: three findings produce three different
// winners across the six permutations of the same set.
func TestTieBreakIsTransitiveAcrossPermutations(t *testing.T) {
	rows := []model.Finding{
		fx("a", "xss", "Alpha", "h.ts", 138, model.SeverityCritical),
		fx("b", "cwe", "Beta", "h.ts", 138, model.SeverityCritical),
		fx("c", "soc2", "Gamma", "h.ts", 138, model.SeverityCritical),
	}
	perms := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	winners := map[string]bool{}
	for _, p := range perms {
		keeper := rows[p[0]]
		for _, i := range p[1:] {
			ch := rows[i]
			if crossAgentPrefers(ch, keeper, findingDetailScore(ch), findingDetailScore(keeper), true) {
				keeper = ch
			}
		}
		winners[keeper.ID] = true
	}
	if len(winners) != 1 {
		t.Fatalf("not transitive: %d different winners across 6 permutations of the "+
			"same 3 findings (%v) — the surviving row depends on goroutine interleaving",
			len(winners), winners)
	}
}

// D1-T4 — the tie-break must not disturb the two rules layered above it.
func TestTieBreakPreservesRollupAndDeterministicRules(t *testing.T) {
	t.Run("rollup parent still wins", func(t *testing.T) {
		parent := fx("p", "cwe", "Zzz last alphabetically", "h.ts", 1, model.SeverityLow)
		parent.IsRollup = true
		member := fx("m", "cwe", "Aaa first alphabetically", "h.ts", 1, model.SeverityCritical)
		if !crossAgentPrefers(parent, member, findingDetailScore(parent), findingDetailScore(member), true) {
			t.Error("a rollup parent must still displace a member regardless of the tie-break")
		}
		if crossAgentPrefers(member, parent, findingDetailScore(member), findingDetailScore(parent), true) {
			t.Error("a member must never displace a rollup parent")
		}
	})

	t.Run("deterministic still beats llm at equal severity", func(t *testing.T) {
		det := fx("d", "cwe", "Zzz", "h.ts", 1, model.SeverityHigh)
		det.Provenance = "skill"
		llm := fx("l", "cwe", "Aaa", "h.ts", 1, model.SeverityHigh)
		llm.Provenance = "llm"
		if !crossAgentPrefers(det, llm, findingDetailScore(det), findingDetailScore(llm), true) {
			t.Error("the 0076 deterministic preference must outrank the tie-break")
		}
	})

	t.Run("a higher score still wins outright", func(t *testing.T) {
		rich := fx("r", "cwe", "Zzz", "h.ts", 1, model.SeverityCritical)
		poor := fx("p", "cwe", "Aaa", "h.ts", 1, model.SeverityLow)
		if !crossAgentPrefers(rich, poor, findingDetailScore(rich), findingDetailScore(poor), true) {
			t.Error("score must still dominate the tie-break")
		}
	})
}

// D1-T5 — the rollback restores the coin flip exactly.
func TestTieBreakRollbackRestoresFirstSeen(t *testing.T) {
	t.Setenv("VULTURE_DEDUP_STABLE_TIEBREAK", "false")
	a := fx("a", "xss", "Alpha", "h.ts", 138, model.SeverityCritical)
	b := fx("b", "xss", "Beta", "h.ts", 138, model.SeverityCritical)
	sa, sb := findingDetailScore(a), findingDetailScore(b)
	if crossAgentPrefers(b, a, sb, sa, true) {
		t.Error("with the tie-break off, an equal-score challenger must NOT displace " +
			"the incumbent — that is the pre-0079 first-seen rule")
	}
}
