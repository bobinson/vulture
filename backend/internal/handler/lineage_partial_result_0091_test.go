package handler

import (
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 — the two states a scan can be in that look like "the agent
// said nothing" but are not the same fact, pinned at the seam that builds the
// per-agent ScanResult.
//
//   - An agent that COMPLETED but predates 0091 sent a result snapshot whose
//     `result_schema` is 0. That is S26: scope is undescribable, deterministic
//     closure still applies.
//   - An agent that was DISPATCHED and never reported (killed by
//     VULTURE_AGENT_PROXY_TIMEOUT_SEC, cancelled on client disconnect, or
//     crashed) sent no snapshot at all. Its findings come from the delta
//     rescue, which is a PARTIAL set by construction, so closing anything on
//     its silence closes rows the scan may well have found.
//
// Folding the second into the first is what let one timed-out agent mark every
// deterministic row it did not manage to re-report as fixed.
func TestSynthesisedResultForSilentAgentIsMarkedNoResult(t *testing.T) {
	seen := map[string]*model.ScanResult{}
	svc := &mockLineageService{
		recordScanOutcomeFn: func(_ *model.Audit, _ *model.Source, agentType string, r *model.ScanResult) error {
			seen[agentType] = r
			return nil
		},
	}
	findings := []model.Finding{
		{AgentType: "cwe", Fingerprint: "fp-cwe", Title: "rescued from deltas"},
		{AgentType: "chaos", Fingerprint: "fp-chaos", Title: "reported normally"},
	}
	// Only `chaos` left a snapshot behind. `cwe` never sent one.
	outcomes := map[string]*model.ScanResult{
		"chaos": {ResultSchema: model.ScanResultSchemaEvidence},
	}

	recordLineageOutcomes(svc, &model.Audit{ID: "a-1"}, &model.Source{ID: "s-1", Path: "/proj"},
		findings, outcomes)

	cwe, ok := seen["cwe"]
	if !ok {
		t.Fatalf("the agent whose findings were rescued from the delta stream must still get a pass")
	}
	if !cwe.NoResultSnapshot {
		t.Fatalf("an agent that was dispatched and never sent a result snapshot must be marked " +
			"NoResultSnapshot, so its partial delta-rescued finding set cannot close rows on silence")
	}
	if chaos := seen["chaos"]; chaos == nil || chaos.NoResultSnapshot {
		t.Fatalf("an agent that DID report must not be marked NoResultSnapshot: %+v", chaos)
	}
}

// TestRollupShadowedLeavesAreRecorded pins the other half of the same problem
// (S21): a leaf finding the agent DID report, which cross-agent dedup then
// replaced with a rollup parent covering the same site, is absent from the
// persisted result for a structural reason and must not be read as repair.
func TestRollupShadowedLeavesAreRecorded(t *testing.T) {
	parent := model.Finding{
		AgentType: "cwe", Category: "CWE-94", FilePath: "src/a.ts", LineStart: 34,
		Title: "Code injection (12 instances)", Fingerprint: "fp-parent",
		IsRollup: true, Provenance: "catalog_rollup",
	}
	leaf := model.Finding{
		AgentType: "asvs", Category: "CWE-94", FilePath: "src/a.ts", LineStart: 34,
		Title: "Code injection", Fingerprint: "fp-leaf", FingerprintV2: "fp2-leaf",
		Provenance: "skill",
	}
	elsewhere := model.Finding{
		AgentType: "asvs", Category: "CWE-94", FilePath: "src/b.ts", LineStart: 9,
		Title: "Code injection", Fingerprint: "fp-elsewhere", Provenance: "skill",
	}

	kept, shadowed := dedupCrossAgentWithShadow([]model.Finding{parent, leaf, elsewhere}, "")

	if len(kept) != 2 {
		t.Fatalf("the parent evicts only the leaf at its own site: kept %d rows", len(kept))
	}
	if !shadowed["fp-leaf"] {
		t.Fatalf("a leaf removed because a ROLLUP PARENT won its key was reported and consolidated, "+
			"not repaired, and must be recorded as shadowed: got %v", shadowed)
	}
	if !shadowed["fp2-leaf"] {
		t.Fatalf("both identities must be recorded, for the same reason reported() consults both: %v", shadowed)
	}
	if shadowed["fp-elsewhere"] || shadowed["fp-parent"] {
		t.Fatalf("only the evicted leaves are shadowed, never the survivors: %v", shadowed)
	}
}

// TestPlainDuplicateEvictionIsNotShadowed is the control. An ordinary
// cross-agent duplicate — two detectors reporting the same thing, neither a
// rollup parent — is a genuine merge, and treating it as "consolidated away"
// would suppress closure for every deduplicated finding in the product.
func TestPlainDuplicateEvictionIsNotShadowed(t *testing.T) {
	a := model.Finding{AgentType: "cwe", Category: "CWE-89", FilePath: "src/q.go", LineStart: 4,
		Title: "SQL injection", Fingerprint: "fp-a", Severity: model.SeverityHigh, CodeSnippet: "x"}
	b := model.Finding{AgentType: "owasp", Category: "CWE-89", FilePath: "src/q.go", LineStart: 4,
		Title: "SQL injection", Fingerprint: "fp-b", Severity: model.SeverityHigh}

	kept, shadowed := dedupCrossAgentWithShadow([]model.Finding{a, b}, "")
	if len(kept) != 1 {
		t.Fatalf("the two agents report one finding: kept %d", len(kept))
	}
	if len(shadowed) != 0 {
		t.Fatalf("a plain cross-agent merge is not a rollup consolidation: %v", shadowed)
	}
}
