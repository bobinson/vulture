package pluginregistry

import "testing"

// TestIsBackendSecret_ProviderKeys is the RED baseline for the denylist gap
// (0065 security review finding): the backend holds ANTHROPIC_API_KEY and
// GEMINI_API_KEY (Claude/Gemini model routing — see localdev launcher + broker),
// but only OPENAI_API_KEY was hard-blocked, so a plugin manifest could declare
// the other provider keys and have docker inject the backend's real credentials
// into the plugin container.
func TestIsBackendSecret_ProviderKeys(t *testing.T) {
	for _, name := range []string{"ANTHROPIC_API_KEY", "GEMINI_API_KEY", "anthropic_api_key"} {
		if !IsBackendSecret(name) {
			t.Errorf("IsBackendSecret(%q) = false, want true (backend-held provider credential)", name)
		}
	}
	// Plugin-namespaced provider tokens are NOT backend secrets (warn-only,
	// still forwardable) — must remain false so this fix doesn't over-block.
	if IsBackendSecret("SEMGREP_APP_TOKEN") {
		t.Error("IsBackendSecret(SEMGREP_APP_TOKEN) = true, want false (plugin's own credential)")
	}
}
