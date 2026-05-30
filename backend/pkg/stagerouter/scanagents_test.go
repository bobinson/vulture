package stagerouter

import (
	"reflect"
	"testing"

	"github.com/vulture/backend/pkg/pluginregistry"
)

func TestDefaultScanAgentTypes_NilRegistry_ReturnsBaseCopy(t *testing.T) {
	base := []string{"chaos", "owasp"}
	out := DefaultScanAgentTypes(nil, base)
	if !reflect.DeepEqual(out, base) {
		t.Errorf("nil registry: expected %v, got %v", base, out)
	}
	// Mutating the result must not alias the input.
	if len(out) > 0 {
		out[0] = "MUTATED"
		if base[0] == "MUTATED" {
			t.Error("result must not alias base slice")
		}
	}
}

func TestDefaultScanAgentTypes_AddsExternalScanPlugins(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPluginWithTier("chaos", true, pluginregistry.TierInTree,
			[]pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}}}),
		mkPluginWithTier("semgrep", true, pluginregistry.TierCommunitySigned,
			[]pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}}}),
		mkPluginWithTier("metasploit", true, pluginregistry.TierUserSupplied,
			[]pluginregistry.Capability{{Phase: "prove", Emits: []string{"proof_result"}}}),
	}
	registry := &fakeRegistry{plugins: plugins}
	base := []string{"chaos", "owasp"}
	out := DefaultScanAgentTypes(registry, base)

	// Expect base preserved + semgrep appended; metasploit excluded
	// (no scan capability); chaos NOT re-added (already in base).
	want := []string{"chaos", "owasp", "semgrep"}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("expected %v, got %v", want, out)
	}
}

func TestDefaultScanAgentTypes_SkipsDisabledExternal(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPluginWithTier("semgrep", false, pluginregistry.TierCommunitySigned, // disabled
			[]pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}}}),
	}
	registry := &fakeRegistry{plugins: plugins}
	out := DefaultScanAgentTypes(registry, []string{"chaos"})
	want := []string{"chaos"}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("disabled plugin should not appear: got %v", out)
	}
}

func TestDefaultScanAgentTypes_DoesNotDuplicateInTree(t *testing.T) {
	// If an in-tree plugin is somehow re-listed in the registry with
	// the same name as base, the dedup map prevents duplicates.
	plugins := []pluginregistry.Plugin{
		mkPluginWithTier("owasp", true, pluginregistry.TierInTree,
			[]pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}}}),
	}
	registry := &fakeRegistry{plugins: plugins}
	out := DefaultScanAgentTypes(registry, []string{"owasp"})
	want := []string{"owasp"}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("expected no duplicate, got %v", out)
	}
}

func TestDefaultScanAgentTypes_PreservesRegistryOrder(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPluginWithTier("z-tool", true, pluginregistry.TierUserSupplied,
			[]pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}}}),
		mkPluginWithTier("a-tool", true, pluginregistry.TierUserSupplied,
			[]pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}}}),
	}
	registry := &fakeRegistry{plugins: plugins}
	out := DefaultScanAgentTypes(registry, nil)
	want := []string{"z-tool", "a-tool"}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("expected registry order preserved (%v), got %v", want, out)
	}
}
