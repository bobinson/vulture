package stagerouter

import (
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// fakeResolver is a test double that always returns the same URL.
type fakeResolver struct{ url string }

func (f *fakeResolver) Resolve(p pluginregistry.Plugin) string { return f.url }

func TestResolveURL_EnvWinsOverConfig(t *testing.T) {
	// Review MAJOR #7: env vars must win over config.ini values
	// (twelve-factor). Snapshot env at construction time, build a
	// resolver whose envURLs contain the override.
	r := &defaultResolver{
		envURLs: map[string]string{"chaos": "http://chaos.env"},
		agents:  map[string]config.AgentConfig{"chaos": {URL: "http://chaos.ini"}},
	}
	p := pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{Name: "chaos"},
		},
	}
	if got := r.Resolve(p); got != "http://chaos.env" {
		t.Errorf("env should win; got %q", got)
	}
}

func TestResolveURL_FallsThroughToManifestDerived(t *testing.T) {
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
	if got := r.Resolve(p); got != "http://agent-semgrep:28100" {
		t.Errorf("manifest-derived URL; got %q", got)
	}
}

func TestResolveURL_ReturnsEmptyWhenUnreachable(t *testing.T) {
	r := &defaultResolver{}
	p := pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin:  pluginregistry.PluginBlock{Name: "ghost"},
			Runtime: pluginregistry.RuntimeBlock{Type: pluginregistry.RuntimeInTree},
		},
	}
	if got := r.Resolve(p); got != "" {
		t.Errorf("expected empty URL for unreachable plugin, got %q", got)
	}
}

func TestResolveURL_ContainerWithoutPortFallsThrough(t *testing.T) {
	r := &defaultResolver{}
	p := pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin:  pluginregistry.PluginBlock{Name: "incomplete"},
			Runtime: pluginregistry.RuntimeBlock{Type: pluginregistry.RuntimeContainer, Port: 0},
		},
	}
	if got := r.Resolve(p); got != "" {
		t.Errorf("container with no port should not produce URL, got %q", got)
	}
}

func TestSnapshotEnvURLs_ExtractsAndNormalises(t *testing.T) {
	t.Setenv("VULTURE_AGENT_CHAOS_URL", "http://chaos")
	t.Setenv("VULTURE_AGENT_SEMGREP_URL", "http://semgrep")
	t.Setenv("VULTURE_AGENT_FOO_BAR_URL", "http://foobar")
	t.Setenv("VULTURE_NOTAGENT_URL", "should-be-ignored")
	t.Setenv("VULTURE_AGENT_CHAOS_HOST", "should-be-ignored")

	got := snapshotEnvURLs()
	if got["chaos"] != "http://chaos" {
		t.Errorf("chaos: %q", got["chaos"])
	}
	if got["semgrep"] != "http://semgrep" {
		t.Errorf("semgrep: %q", got["semgrep"])
	}
	// FOO_BAR maps to both foo_bar and foo-bar so the resolver
	// can find either slug form. Plugin schema constrains names
	// to one or the other; we don't try to disambiguate.
	if got["foo_bar"] != "http://foobar" {
		t.Errorf("foo_bar: %q", got["foo_bar"])
	}
	if got["foo-bar"] != "http://foobar" {
		t.Errorf("foo-bar (mirror): %q", got["foo-bar"])
	}
	if _, ok := got["notagent"]; ok {
		t.Errorf("non-AGENT env var leaked into snapshot: %v", got)
	}
}
