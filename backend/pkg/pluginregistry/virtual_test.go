package pluginregistry

import (
	"testing"

	"github.com/vulture/backend/pkg/agentregistry"
)

func TestAllVirtualPlugins_CoversEveryInTreeAgent(t *testing.T) {
	plugins := AllVirtualPlugins()
	if len(plugins) != len(agentregistry.AllAgents) {
		t.Fatalf("virtual plugin count = %d; want %d (matches AllAgents)",
			len(plugins), len(agentregistry.AllAgents))
	}
	have := make(map[string]bool, len(plugins))
	for _, p := range plugins {
		have[p.Name()] = true
		if p.Source != "in-tree" {
			t.Errorf("plugin %q source = %q; want in-tree", p.Name(), p.Source)
		}
		if !p.Enabled {
			t.Errorf("plugin %q should default to Enabled", p.Name())
		}
		if !p.IsInTree() {
			t.Errorf("plugin %q should report IsInTree()", p.Name())
		}
	}
	for _, e := range agentregistry.AllAgents {
		if !have[e.Type] {
			t.Errorf("AllAgents type %q has no virtual plugin", e.Type)
		}
	}
}

func TestVirtualManifest_PhaseRoutedFromAgentType(t *testing.T) {
	cases := []struct {
		typ   string
		phase string
	}{
		{"chaos", PhaseScan},
		{"prove", PhaseProve},
		{"discover", PhaseDiscover},
		{"cwe", PhaseScan},
	}
	for _, c := range cases {
		m := VirtualManifestForInTreeAgent(agentregistry.AgentRegistryEntry{
			Type:   c.typ,
			Name:   c.typ,
			Module: c.typ + "_agent.main:app",
		})
		if len(m.Capabilities) != 1 || m.Capabilities[0].Phase != c.phase {
			t.Errorf("type %q -> phase %q; want %q",
				c.typ, m.Capabilities[0].Phase, c.phase)
		}
	}
}

func TestVirtualManifest_PassesValidation(t *testing.T) {
	for _, p := range AllVirtualPlugins() {
		m := p.Manifest
		if err := ValidateManifest(&m); err != nil {
			t.Errorf("virtual manifest for %q failed validation: %v",
				p.Name(), err)
		}
	}
}

// AC 14 (feature 0050, BLOCKER #4): Plugin.Name() MUST equal the
// underlying AgentRegistryEntry.Type for every in-tree virtual
// manifest, in registry order (index-aligned).
//
// Why: the 0050 normalisation layer keys per-plugin maps by
// Plugin.Name(). If the synthesised manifest name drifts from the
// AgentRegistryEntry.Type it was built from, prior findings emitted
// by an in-tree agent (carrying AgentType = entry.Type) would fail
// to find their plugin's per-plugin map. This test catches that
// drift at CI time, before any layer wiring runs.
//
// Implementation invariant: AllVirtualPlugins() iterates
// agentregistry.AllAgents in order, so output[i].Name() must equal
// AllAgents[i].Type for every i.
func TestAllVirtualPlugins_NameMatchesAgentRegistryType_AC14(t *testing.T) {
	plugins := AllVirtualPlugins()
	if len(plugins) != len(agentregistry.AllAgents) {
		t.Fatalf("virtual plugin count (%d) != AllAgents count (%d); index alignment broken",
			len(plugins), len(agentregistry.AllAgents))
	}
	for i, e := range agentregistry.AllAgents {
		if plugins[i].Name() != e.Type {
			t.Errorf("AllVirtualPlugins()[%d].Name() = %q; want %q (AgentRegistryEntry.Type)",
				i, plugins[i].Name(), e.Type)
		}
	}
}
