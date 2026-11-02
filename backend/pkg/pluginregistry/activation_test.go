package pluginregistry

import (
	"reflect"
	"testing"
)

func extPlugin(name string, enabled bool) Plugin {
	return Plugin{
		Enabled: enabled,
		Manifest: Manifest{
			Plugin:  PluginBlock{Name: name},
			Trust:   TrustBlock{Tier: TierCommunitySigned},
			Runtime: RuntimeBlock{Type: "container"},
		},
	}
}

func inTreePlugin(name string, enabled bool) Plugin {
	return Plugin{
		Enabled: enabled,
		Manifest: Manifest{
			Plugin:  PluginBlock{Name: name},
			Trust:   TrustBlock{Tier: TierInTree},
			Runtime: RuntimeBlock{Type: RuntimeInTree},
		},
	}
}

func enabledByName(plugins []Plugin) map[string]bool {
	m := make(map[string]bool, len(plugins))
	for _, p := range plugins {
		m[p.Name()] = p.Enabled
	}
	return m
}

func TestParseActivationSpec(t *testing.T) {
	got := parseActivationSpec(" semgrep, Trivy ,, ")
	want := []string{"semgrep", "trivy"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseActivationSpec = %v, want %v", got, want)
	}
	if len(parseActivationSpec("   ")) != 0 {
		t.Error("whitespace-only spec should yield no tokens")
	}
}

func TestApplyActivationList(t *testing.T) {
	// chaos = in-tree built-in (must stay enabled); semgrep + trivy = external.
	base := func() []Plugin {
		return []Plugin{
			inTreePlugin("chaos", true),
			extPlugin("semgrep", false),
			extPlugin("trivy", false),
		}
	}

	t.Run("explicit list enables only named externals", func(t *testing.T) {
		out, unknown := applyActivationList(base(), "semgrep")
		en := enabledByName(out)
		if !en["semgrep"] {
			t.Error("semgrep should be enabled")
		}
		if en["trivy"] {
			t.Error("trivy not in list -> must be disabled")
		}
		if !en["chaos"] {
			t.Error("INVARIANT VIOLATED: in-tree chaos must stay enabled")
		}
		if len(unknown) != 0 {
			t.Errorf("unexpected unknowns: %v", unknown)
		}
	})

	t.Run("all enables every external, leaves in-tree", func(t *testing.T) {
		out, unknown := applyActivationList(base(), "all")
		en := enabledByName(out)
		if !en["semgrep"] || !en["trivy"] || !en["chaos"] {
			t.Errorf("all: expected every plugin enabled, got %v", en)
		}
		if unknown != nil {
			t.Errorf("all: expected no unknowns, got %v", unknown)
		}
	})

	t.Run("empty disables all externals but NOT in-tree", func(t *testing.T) {
		out, _ := applyActivationList(base(), "")
		en := enabledByName(out)
		if en["semgrep"] || en["trivy"] {
			t.Error("empty spec must disable external plugins")
		}
		if !en["chaos"] {
			t.Error("INVARIANT VIOLATED: empty spec must NOT disable in-tree chaos")
		}
	})

	t.Run("none disables all externals but NOT in-tree", func(t *testing.T) {
		// start with externals enabled to prove they get turned off
		in := []Plugin{inTreePlugin("chaos", true), extPlugin("semgrep", true)}
		out, unknown := applyActivationList(in, "none")
		en := enabledByName(out)
		if en["semgrep"] {
			t.Error("none must disable semgrep")
		}
		if !en["chaos"] {
			t.Error("INVARIANT VIOLATED: none must NOT disable in-tree chaos")
		}
		if unknown != nil {
			t.Errorf("none: expected no unknowns, got %v", unknown)
		}
	})

	t.Run("unknown names are reported, valid ones still applied", func(t *testing.T) {
		out, unknown := applyActivationList(base(), "semgrep,bogus")
		if !enabledByName(out)["semgrep"] {
			t.Error("semgrep should be enabled")
		}
		if !reflect.DeepEqual(unknown, []string{"bogus"}) {
			t.Errorf("unknown = %v, want [bogus]", unknown)
		}
	})

	t.Run("does not mutate the input slice", func(t *testing.T) {
		in := base()
		_, _ = applyActivationList(in, "semgrep")
		if in[1].Enabled { // semgrep started false
			t.Error("applyActivationList mutated the caller's slice")
		}
	})
}
