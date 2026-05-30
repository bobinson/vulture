package stagerouter

import "github.com/vulture/backend/pkg/pluginregistry"

// DefaultScanAgentTypes returns the agent-type slugs the pipeline
// should put into `audit.Types` for the default scan stage when the
// pipeline config doesn't pin an explicit list.
//
// Behaviour:
//
//  1. Start from `base` — the legacy in-tree default scan set
//     (typically `agentregistry.ScanAgentTypes()`, which already
//     filters Optional + pipeline-stage agents).
//  2. Append every Enabled, non-in-tree plugin in the registry that
//     has at least one scan-phase capability, preserving registry
//     order and skipping names already in `base` (no duplicates).
//
// The function deliberately does NOT add in-tree plugins from the
// registry beyond `base` — `base` already encodes the operator-facing
// rules (Optional flag, pipeline-stage exclusion) that the registry
// alone cannot express today. External plugins inherit the same
// exclusions implicitly: pipeline-stage plugins (prove/discover) are
// matched by `Capability.Phase`, not by the slug, so a third-party
// "scan" capability with the name "prove" still wouldn't be a scan
// agent for this purpose.
func DefaultScanAgentTypes(registry pluginregistry.Registry, base []string) []string {
	if registry == nil {
		return append([]string(nil), base...)
	}
	out := append(make([]string, 0, len(base)+4), base...)
	seen := make(map[string]bool, len(base))
	for _, b := range base {
		seen[b] = true
	}
	for _, p := range registry.Enabled() {
		if p.Manifest.Trust.Tier == pluginregistry.TierInTree {
			continue
		}
		if !hasScanCapability(p) {
			continue
		}
		name := p.Name()
		if seen[name] {
			continue
		}
		out = append(out, name)
		seen[name] = true
	}
	return out
}

func hasScanCapability(p pluginregistry.Plugin) bool {
	for _, c := range p.Manifest.Capabilities {
		if c.Phase == pluginregistry.PhaseScan {
			return true
		}
	}
	return false
}
