package pluginregistry

import (
	"fmt"

	"github.com/vulture/backend/pkg/agentregistry"
)

// VirtualManifestForInTreeAgent synthesises a vulture-plugin/1.0
// manifest for one of the legacy in-tree agents declared in
// agentregistry.AllAgents.
//
// The synthesised manifest preserves the prior runtime contract
// (same port, same Python entry point) so the registry can route
// to in-tree agents without any code path change in 0048. Feature
// 0049 will use the same manifest for capability-based dispatch.
func VirtualManifestForInTreeAgent(e agentregistry.AgentRegistryEntry) Manifest {
	phase := phaseForAgentType(e.Type)
	cap := Capability{
		Phase:   phase,
		Emits:   emitsForPhase(phase),
		TimeoutS: 1800,
	}
	return Manifest{
		Plugin: PluginBlock{
			Name:        e.Type,
			DisplayName: e.Name,
			Version:     "1.0.0",
			APIVersion:  APIVersionV1,
			Publisher:   "vulture-core",
			Description: fmt.Sprintf("In-tree %s agent", e.Name),
			License:     "Apache-2.0",
		},
		Trust: TrustBlock{
			Tier: TierInTree,
		},
		Runtime: RuntimeBlock{
			Type:       RuntimeInTree,
			ModulePath: e.Module,
		},
		Capabilities: []Capability{cap},
	}
}

// AllVirtualPlugins returns one in-tree Plugin per entry in
// agentregistry.AllAgents, ready to be merged into a Registry.
func AllVirtualPlugins() []Plugin {
	out := make([]Plugin, 0, len(agentregistry.AllAgents))
	for _, e := range agentregistry.AllAgents {
		out = append(out, Plugin{
			Manifest: VirtualManifestForInTreeAgent(e),
			Source:   "in-tree",
			Enabled:  true,
		})
	}
	return out
}

// phaseForAgentType maps an in-tree agent type to its stage. Most
// agents are scanners; prove + discover are their own stages. Add
// to this table when a new in-tree agent doesn't fit the default.
func phaseForAgentType(t string) string {
	switch t {
	case "prove":
		return PhaseProve
	case "discover":
		return PhaseDiscover
	default:
		return PhaseScan
	}
}

// emitsForPhase returns the canonical event set a stage must emit.
// Aligned with the schema's `allOf` rules at
// docs/spec/plugin-v1/manifest.schema.json.
func emitsForPhase(phase string) []string {
	common := []string{"run_started", "run_finished", "thinking", "progress", "result"}
	switch phase {
	case PhaseDiscover:
		return append(common, "discover_result")
	case PhaseValidate:
		return append(common, "validation_update")
	case PhaseProve:
		return append(common, "proof_phase", "proof_plan", "proof_attempt", "proof_result", "proof_summary")
	default:
		return append(common, "finding", "dedup_stats", "token_savings")
	}
}
