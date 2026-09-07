package service

import "testing"

// Feature 0082 C4 — why PriorFinding must carry the validation BLOB, not just
// the status string.
//
// `applyMemoryPriorIfEnabled` (handler/stream_handler.go:1000-1005) synthesises
// `{status, confidence, checks: []}` for any finding whose Validation is nil,
// then re-votes. Vote() recomputes from a 0.5 base plus the check weights
// (validation_voter.go:205-209) — it never reads the status or confidence
// fields. So a synthesised blob carries the VERDICT but not the EVIDENCE for
// it, and the re-vote discards the verdict entirely.
//
// Before C4 that was the OWASP path: PriorFinding had ValidationStatus and
// ValidationConfidence but no Validation map, so every carried verdict arrived
// evidence-free and one memory label was enough to invert it.

const memoryInheritedTP = 0.40

func TestSynthesisedBlobLosesTheInheritedVerdict(t *testing.T) {
	// What the pre-C4 transport produced: the verdict arrived as a bare
	// string, so the synthesised blob had NO checks to justify it.
	synthesised := []VoterCheck{
		{ID: "memory", Weight: memoryInheritedTP, Result: "inherited_tp"},
	}
	got := Vote(synthesised)

	// NON-VACUITY: if the memory check carried no weight this proves nothing.
	if memoryInheritedTP == 0 {
		t.Fatal("non-vacuity: the memory check must carry weight")
	}
	if got.Confidence <= 0.5 {
		t.Fatalf("expected the memory label to raise confidence, got %.2f", got.Confidence)
	}
	t.Logf("evidence-free re-vote: confidence %.2f status %q "+
		"(the inherited likely_fp/0.05 is simply gone)", got.Confidence, got.Status)
}

func TestCarriedBlobPreservesTheInheritedVerdict(t *testing.T) {
	// What C4 delivers: the blob arrives with the checks that EARNED the
	// verdict, so the re-vote reconsiders them instead of starting blank.
	// A likely_fp row is one whose evidence is strongly negative.
	carried := []VoterCheck{
		{ID: "anchor", Weight: -1.0, Result: "absent"},
		{ID: "memory", Weight: memoryInheritedTP, Result: "inherited_tp"},
	}
	got := Vote(carried)

	synthesised := Vote([]VoterCheck{{ID: "memory", Weight: memoryInheritedTP, Result: "inherited_tp"}})
	if got.Confidence >= synthesised.Confidence {
		t.Errorf("carrying the blob must preserve the negative evidence: "+
			"carried=%.2f synthesised=%.2f", got.Confidence, synthesised.Confidence)
	}
	if got.Status == synthesised.Status {
		t.Errorf("carried and synthesised reached the same status %q — "+
			"the blob is not affecting the outcome, so C4 buys nothing", got.Status)
	}
	t.Logf("carried blob: confidence %.2f status %q (vs synthesised %.2f / %q)",
		got.Confidence, got.Status, synthesised.Confidence, synthesised.Status)
}
