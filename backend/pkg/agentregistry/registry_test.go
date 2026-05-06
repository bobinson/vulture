package agentregistry

import (
	"slices"
	"testing"
)

// TestScanAgentTypes_ExcludesProveAndDiscover documents that the
// default scan set never includes the prove or discover agents — those
// are pipeline stages, not scanners.
func TestScanAgentTypes_ExcludesProveAndDiscover(t *testing.T) {
	types := ScanAgentTypes()
	for _, banned := range []string{"prove", "discover"} {
		if slices.Contains(types, banned) {
			t.Errorf("ScanAgentTypes() = %v; should not contain %q", types, banned)
		}
	}
}

// TestScanAgentTypes_ExcludesOptional documents that the default scan
// set excludes Optional agents (currently do178c). Operators must
// opt-in via --types do178c on the CLI or by ticking the agent in the
// frontend.
func TestScanAgentTypes_ExcludesOptional(t *testing.T) {
	types := ScanAgentTypes()
	if slices.Contains(types, "do178c") {
		t.Errorf("ScanAgentTypes() = %v; should not contain optional agent %q", types, "do178c")
	}
}

// TestAllScanAgentTypes_IncludesOptional verifies that the
// "everything" view exposes optional agents — the frontend agent
// selector and CLI --types help text use this so users can discover
// them and opt-in.
func TestAllScanAgentTypes_IncludesOptional(t *testing.T) {
	types := AllScanAgentTypes()
	if !slices.Contains(types, "do178c") {
		t.Errorf("AllScanAgentTypes() = %v; should contain optional agent %q", types, "do178c")
	}
	for _, banned := range []string{"prove", "discover"} {
		if slices.Contains(types, banned) {
			t.Errorf("AllScanAgentTypes() = %v; should not contain pipeline stage %q", types, banned)
		}
	}
}

// TestDO178C_MarkedOptional locks in the contract that do178c is
// flagged Optional in the registry. Removing the flag accidentally
// would bring the agent back into the default scan set.
func TestDO178C_MarkedOptional(t *testing.T) {
	for _, e := range AllAgents {
		if e.Type == "do178c" {
			if !e.Optional {
				t.Errorf("registry entry for do178c should have Optional=true")
			}
			return
		}
	}
	t.Errorf("no registry entry for do178c")
}

// TestNonOptionalAgents_StayInDefaultSet is a guardrail: agents not
// flagged Optional must remain in the default ScanAgentTypes() (other
// than the pipeline stages prove/discover). Catches accidental
// regressions where someone marks a load-bearing agent Optional.
func TestNonOptionalAgents_StayInDefaultSet(t *testing.T) {
	def := ScanAgentTypes()
	for _, e := range AllAgents {
		if e.Type == "prove" || e.Type == "discover" {
			continue
		}
		if e.Optional {
			continue
		}
		if !slices.Contains(def, e.Type) {
			t.Errorf("non-optional agent %q is missing from ScanAgentTypes() = %v", e.Type, def)
		}
	}
}
