package localdev

import "testing"

// Feature 0102: the docker CLI that launches plugin containers is a child of
// the backend. It gets the host environment minus every backend credential
// and every injection vector, with no agent keep-set, no passthrough and no
// rollback hatch: a name-only `-e NAME` would otherwise forward whatever the
// backend holds under that name into a plugin container.
func TestPluginCLIEnv_DropsSecretsAndHazards(t *testing.T) {
	for name, value := range map[string]string{
		"VULTURE_AGENT_TOKEN": "shared-agent-token",
		"VULTURE_JWT_SECRET":  "jwt-signing-key",
		"VULTURE_DB_DSN":      "postgres://u:p@db/vulture",
		"OPENAI_API_KEY":      "provider-key",
		"LD_PRELOAD":          "/nonexistent/inject.so",
		"PYTHONSTARTUP":       "/nonexistent/inject.py",
		"DOCKER_CONFIG":       "/nonexistent/docker-config",
		"SEMGREP_APP_TOKEN":   "plugin-declared-credential",
		// The agent filter's hatches must not reach the docker CLI filter.
		"VULTURE_AGENT_ENV_SCRUB":       "false",
		"VULTURE_AGENT_ENV_PASSTHROUGH": "VULTURE_AGENT_TOKEN,VULTURE_JWT_SECRET,LD_PRELOAD",
	} {
		t.Setenv(name, value)
	}

	env := PluginCLIEnvFromHost()

	for _, denied := range []string{
		"VULTURE_AGENT_TOKEN", "VULTURE_JWT_SECRET", "VULTURE_DB_DSN", "OPENAI_API_KEY",
		"LD_PRELOAD", "PYTHONSTARTUP",
	} {
		if has(t, env, denied) {
			t.Errorf("the docker CLI environment keeps %s", denied)
		}
	}
	// What docker itself needs, and a plugin-declared variable the argv
	// forwards by name, survive.
	for _, kept := range []string{"PATH", "DOCKER_CONFIG", "SEMGREP_APP_TOKEN"} {
		if !has(t, env, kept) {
			t.Errorf("the docker CLI environment lost %s", kept)
		}
	}
}
