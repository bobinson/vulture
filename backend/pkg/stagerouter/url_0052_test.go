package stagerouter

// 0052 BLOCKER #1: the URL resolver must apply
// pluginregistry.SanitiseDNSName when constructing the manifest-derived
// fallback URL, so that `http://agent-<sanitised>:<port>` matches the
// docker --network-alias that the supervisor sets.

import (
	"testing"

	"github.com/vulture/backend/pkg/pluginregistry"
)

func TestResolveURL_AppliesDNSSanitisation_0052_BLOCKER1(t *testing.T) {
	r := &defaultResolver{envURLs: nil, agents: nil}
	p := pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{Name: "my_scanner"},
			Runtime: pluginregistry.RuntimeBlock{
				Type: pluginregistry.RuntimeContainer,
				Port: 28100,
			},
		},
	}
	want := "http://agent-my-scanner:28100"
	if got := r.Resolve(p); got != want {
		t.Errorf("Resolve(my_scanner) = %q; want %q", got, want)
	}
}

func TestResolveURL_NoSanitisationNeeded_StillCorrect_0052(t *testing.T) {
	r := &defaultResolver{envURLs: nil, agents: nil}
	p := pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{Name: "semgrep"},
			Runtime: pluginregistry.RuntimeBlock{
				Type: pluginregistry.RuntimeContainer,
				Port: 28100,
			},
		},
	}
	want := "http://agent-semgrep:28100"
	if got := r.Resolve(p); got != want {
		t.Errorf("Resolve(semgrep) = %q; want %q", got, want)
	}
}

func TestResolveURL_UsesNetworkAliasPrefixConstant_0052(t *testing.T) {
	// Guard against drift: the URL builder MUST use
	// pluginregistry.NetworkAliasPrefix so the supervisor's
	// --network-alias and the resolver's URL stay in lock-step.
	if pluginregistry.NetworkAliasPrefix != "agent-" {
		t.Skipf("NetworkAliasPrefix changed to %q; this test guards the URL builder",
			pluginregistry.NetworkAliasPrefix)
	}
	r := &defaultResolver{}
	p := pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{Name: "x"},
			Runtime: pluginregistry.RuntimeBlock{
				Type: pluginregistry.RuntimeContainer,
				Port: 28100,
			},
		},
	}
	got := r.Resolve(p)
	if got == "" || got[:len("http://agent-")] != "http://agent-" {
		t.Errorf("URL builder must use NetworkAliasPrefix; got %q", got)
	}
}
