package handler

import (
	"testing"

	"github.com/vulture/backend/internal/model"
)

// THE TWO TIERS EMIT DIFFERENT PATH FORMS FOR THE SAME FILE, AND THE DEDUP KEY
// TAKES THEM AT FACE VALUE.
//
// Feature 0079 A1 measured it and built the fix: the deterministic tier reports
// an ABSOLUTE path, the LLM tier a RELATIVE one, "zero exceptions either way",
// so crossAgentKey — which interpolates FilePath raw — can never collide a
// deterministic row with an LLM row describing the same weakness at the same
// line. The fix was shipped behind VULTURE_FINDING_PATH_CANON and defaulted
// OFF, justified by a +114% benchmark. That benchmark measured OBSERVE, which
// runs a whole second delta pass; ENFORCE adds one RelToRoot call per finding
// to the loop that already exists, measured here at ~+13% (see
// path_canon_bench_test.go).
//
// Measured on the live store while the default stood at off: 8,347 lineage
// rows carry an absolute path and 2,414 a relative one, and one line of code —
// server/middleware/requestContext.js:4, CWE-20 — accumulated a separate row
// per tier.
//
// These tests are about the DEFAULT, not the mechanism: the mechanism is
// covered by path_canon_test.go and is not in question.

// splitPair is one weakness reported by both tiers: identical file, category
// and line, differing only in the path form each tier emits — the shape 0079
// measured, and the shape the live duplicate has.
func splitPair(root, rel string) (model.Finding, model.Finding) {
	det := model.Finding{
		AgentType: "cwe", Provenance: "skill", Severity: model.SeverityMedium,
		Category: "CWE-20", Title: "Missing input validation",
		FilePath: root + "/" + rel, LineStart: 4, LineEnd: 4,
		CheckID: "cwe.input_validation.missing_validation",
	}
	llm := model.Finding{
		AgentType: "cwe", Provenance: "llm", Severity: model.SeverityMedium,
		Category: "CWE-20", Title: "Client-supplied x-request-id header trusted without validation",
		FilePath: rel, LineStart: 4, LineEnd: 4,
	}
	return det, llm
}

// TestOneWeaknessSurvivesTheTierPathSplitByDefault is the contract: shipping
// defaults alone must not let one weakness become two findings.
func TestOneWeaknessSurvivesTheTierPathSplitByDefault(t *testing.T) {
	root := "/home/user/danger/blu-simulator"
	det, llm := splitPair(root, "server/middleware/requestContext.js")

	kept, _ := dedupCrossAgentWithShadow([]model.Finding{det, llm}, root)

	if len(kept) != 1 {
		paths := make([]string, 0, len(kept))
		for _, f := range kept {
			paths = append(paths, f.Provenance+":"+f.FilePath)
		}
		t.Fatalf("one weakness at one line reported by both tiers must dedup to ONE finding on "+
			"shipping defaults, got %d: %v. The two rows differ only in the path form each tier "+
			"emits, and the cross-agent key compares that string raw.", len(kept), paths)
	}
	// VULTURE_DEDUP_PREFER_DETERMINISTIC is documented as 0076 re-anchoring's
	// hard prerequisite; it can only arbitrate a collision that occurs.
	if kept[0].Provenance != "skill" {
		t.Errorf("the deterministic row must win the collision (VULTURE_DEDUP_PREFER_DETERMINISTIC), got %q",
			kept[0].Provenance)
	}
}

// TestTierPathSplitDedupIsScopedToTheSameWeakness: canonicalising the key must
// not merge two DIFFERENT weaknesses that happen to share a line. 0079 found
// exactly this hazard — one tainted variable carrying both CWE-601 and
// CWE-918 — and added the coarse-category veto for it.
func TestTierPathSplitDedupIsScopedToTheSameWeakness(t *testing.T) {
	root := "/srv/app"
	redirect := model.Finding{
		AgentType: "cwe", Provenance: "skill", Severity: model.SeverityHigh,
		Category: "CWE-601", Title: "Open redirect", FilePath: root + "/src/upload.ts", LineStart: 19,
	}
	ssrf := model.Finding{
		AgentType: "cwe", Provenance: "llm", Severity: model.SeverityHigh,
		Category: "CWE-918", Title: "Server-side request forgery", FilePath: "src/upload.ts", LineStart: 19,
	}
	kept, _ := dedupCrossAgentWithShadow([]model.Finding{redirect, ssrf}, root)
	if len(kept) != 2 {
		t.Fatalf("two DIFFERENT weaknesses at one line must both survive, got %d — canonicalising "+
			"the path must not merge across CWE ids", len(kept))
	}
}

// TestTierPathSplitDedupLeavesDistinctFilesAlone: the merge must key on the
// canonical path, not merely ignore the path.
func TestTierPathSplitDedupLeavesDistinctFilesAlone(t *testing.T) {
	root := "/srv/app"
	a, _ := splitPair(root, "src/a.js")
	_, b := splitPair(root, "src/b.js")
	kept, _ := dedupCrossAgentWithShadow([]model.Finding{a, b}, root)
	if len(kept) != 2 {
		t.Fatalf("the same weakness in two different files must stay two findings, got %d", len(kept))
	}
}

// TestTierPathSplitDedupWithoutARootIsUnchanged: the replay path passes root ""
// (it has no source on hand) and must behave exactly as before.
func TestTierPathSplitDedupWithoutARootIsUnchanged(t *testing.T) {
	det, llm := splitPair("/srv/app", "src/a.js")
	kept, _ := dedupCrossAgentWithShadow([]model.Finding{det, llm}, "")
	if len(kept) != 2 {
		t.Fatalf("with no source root the paths cannot be related and both rows must survive, got %d", len(kept))
	}
}

// THE ARBITRATION THIS FLIP MAKES LIVE.
//
// VULTURE_DEDUP_PREFER_DETERMINISTIC is documented as 0076 re-anchoring's hard
// prerequisite, but 0079 A1 found it VACUOUS: with the key uncanonicalised a
// det row and an llm row can never share one, so the branch that arbitrates
// between them was unreachable. Enforcing canonicalisation is what reaches it.
// 0079 D1 saw this coming — its stable tie-break comment says the total order
// "lands BEFORE the key changes in the rest of 0079 because each of them
// manufactures collisions that do not exist today". These pin the arbitration
// now that collisions do exist.
func TestTierPathSplitArbitrationPrefersDeterministicAtEqualSeverity(t *testing.T) {
	root := "/srv/app"
	det, llm := splitPair(root, "src/a.js") // both medium
	// Both orderings: arbitration must not depend on which agent's goroutine
	// reached the channel first.
	for _, order := range [][]model.Finding{{det, llm}, {llm, det}} {
		kept, _ := dedupCrossAgentWithShadow(order, root)
		if len(kept) != 1 {
			t.Fatalf("expected one survivor, got %d", len(kept))
		}
		if kept[0].Provenance != "skill" {
			t.Errorf("at equal severity the deterministic row must win regardless of arrival "+
				"order, got %q", kept[0].Provenance)
		}
	}
}

// The one case 0075's behaviour is deliberately unchanged: a strictly MORE
// severe LLM row still displaces the deterministic one. Enforcing the key must
// not quietly turn the preference into "deterministic always wins".
func TestTierPathSplitArbitrationYieldsToAStrictlyMoreSevereLLMRow(t *testing.T) {
	root := "/srv/app"
	det, llm := splitPair(root, "src/a.js")
	llm.Severity = model.SeverityCritical // det stays medium
	for _, order := range [][]model.Finding{{det, llm}, {llm, det}} {
		kept, _ := dedupCrossAgentWithShadow(order, root)
		if len(kept) != 1 {
			t.Fatalf("expected one survivor, got %d", len(kept))
		}
		if kept[0].Provenance != "llm" || kept[0].Severity != model.SeverityCritical {
			t.Errorf("a strictly more severe LLM row must survive the collision, got %q/%q",
				kept[0].Provenance, kept[0].Severity)
		}
	}
}
