package pluginsupervisor

import (
	"testing"

	"github.com/vulture/backend/pkg/pluginregistry"
)

func TestBuildProbeURL_LocalModeUsesLocalhost(t *testing.T) {
	plug := pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{Name: "semgrep"},
			Runtime: pluginregistry.RuntimeBlock{
				Type:           pluginregistry.RuntimeContainer,
				Port:           28011,
				HealthEndpoint: "/health",
			},
		},
	}
	if got := buildProbeURL(plug, true); got != "http://localhost:28011/health" {
		t.Errorf("local mode probe URL = %q, want http://localhost:28011/health", got)
	}
	if got := buildProbeURL(plug, false); got != "http://agent-semgrep:28011/health" {
		t.Errorf("compose probe URL = %q, want http://agent-semgrep:28011/health", got)
	}
}
