package stagerouter

// Feature 0058 T1 — routing lock (LLD R2, decision 1).
//
// Semgrep is EXPLICIT OPT-IN PER SCAN: the user's tick is the gate.
// These tests pin DefaultScanAgentTypes so that:
//   (a) when `semgrep` IS in the selected base set it appears exactly
//       once in the result (no duplicate append from the registry), and
//   (b) when `semgrep` is NOT in the base set it is NEVER auto-added,
//       even though the bundled semgrep plugin is Enabled + in-tree +
//       scan-capable in the registry.
//
// These are contract LOCKS: they pin behavior the router already has so
// the GREEN team cannot regress it while wiring 0058 augmentation.
// Fixtures mirror scanagents_test.go (fakeRegistry / mkPluginWithTier
// from router_test.go, same package).

import (
	"testing"

	"github.com/vulture/backend/pkg/pluginregistry"
)

// semgrepInTreeRegistry returns a registry whose only entry is the
// bundled (in-tree, Enabled) semgrep plugin with a scan capability —
// the 0053 reference plugin as registered in a real deployment.
func semgrepInTreeRegistry() pluginregistry.Registry {
	return &fakeRegistry{plugins: []pluginregistry.Plugin{
		mkPluginWithTier("semgrep", true, pluginregistry.TierInTree,
			[]pluginregistry.Capability{{Phase: pluginregistry.PhaseScan, Emits: []string{"finding"}}}),
	}}
}

func countOf(ss []string, want string) int {
	n := 0
	for _, s := range ss {
		if s == want {
			n++
		}
	}
	return n
}

func TestDefaultScanAgentTypes_SemgrepTicked_AppearsExactlyOnce(t *testing.T) {
	out := DefaultScanAgentTypes(semgrepInTreeRegistry(), []string{"cwe", "semgrep"})
	if got := countOf(out, "semgrep"); got != 1 {
		t.Errorf("base=[cwe semgrep]: semgrep must appear exactly once, got %d occurrences in %v", got, out)
	}
	if got := countOf(out, "cwe"); got != 1 {
		t.Errorf("base=[cwe semgrep]: cwe must appear exactly once, got %d occurrences in %v", got, out)
	}
}

func TestDefaultScanAgentTypes_SemgrepUnticked_NeverAutoAdded(t *testing.T) {
	out := DefaultScanAgentTypes(semgrepInTreeRegistry(), []string{"cwe"})
	if got := countOf(out, "semgrep"); got != 0 {
		t.Errorf("base=[cwe]: semgrep must NOT be auto-added (user tick is the gate — LLD decision 1); got %v", out)
	}
	if got := countOf(out, "cwe"); got != 1 {
		t.Errorf("base=[cwe]: cwe must be preserved exactly once, got %v", out)
	}
}
