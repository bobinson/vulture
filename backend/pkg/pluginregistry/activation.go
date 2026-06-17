package pluginregistry

import "strings"

// parseActivationSpec splits a VULTURE_PLUGINS value into normalized
// (trimmed, lower-cased, non-empty) tokens.
func parseActivationSpec(spec string) []string {
	parts := strings.Split(spec, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.ToLower(strings.TrimSpace(p)); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// applyActivationList applies the VULTURE_PLUGINS allow-list to the discovered
// plugins and returns the adjusted slice plus any list tokens that matched no
// (external) plugin.
//
// Semantics (authoritative, runtime-only):
//   - "all"          -> every EXTERNAL plugin enabled.
//   - ""/"none"      -> every EXTERNAL plugin disabled.
//   - "a,b,c"        -> exactly those EXTERNAL plugins enabled, all others off.
//
// In-tree built-in agents (chaos/owasp/…) are NEVER touched — they're governed
// by state.toml, not by this list. This is the load-bearing safety property:
// VULTURE_PLUGINS=semgrep must not switch off the core agents.
func applyActivationList(plugins []Plugin, spec string) (out []Plugin, unknown []string) {
	tokens := parseActivationSpec(spec)
	all, none := false, false
	want := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		switch t {
		case "all":
			all = true
		case "none":
			none = true
		default:
			want[t] = true
		}
	}

	out = make([]Plugin, len(plugins))
	copy(out, plugins)
	matched := make(map[string]bool, len(want))
	for i := range out {
		if out[i].IsInTree() {
			continue // built-in agents are not governed by VULTURE_PLUGINS
		}
		switch {
		case all:
			out[i].Enabled = true
		case none:
			out[i].Enabled = false
		default:
			name := strings.ToLower(out[i].Name())
			out[i].Enabled = want[name]
			if want[name] {
				matched[name] = true
			}
		}
	}

	if all || none {
		return out, nil // sentinels never produce "unknown" warnings
	}
	for _, t := range tokens {
		if !matched[t] {
			unknown = append(unknown, t)
		}
	}
	return out, unknown
}
