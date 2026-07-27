package pluginregistry

import "strings"

// secretEnvExact are the backend's OWN credentials — never forwardable
// to a plugin container. Single source of truth (0065 §M7): imported by
// both argv.go (launch-time) and manifest.go (install-time).
var secretEnvExact = map[string]bool{
	"VULTURE_JWT_SECRET": true, "VULTURE_DB_DSN": true, "VULTURE_DB_PATH": true,
	"VULTURE_AGENT_TOKEN": true, "VULTURE_WEBHOOK_SECRET": true,
	"VULTURE_LLM_BROKER_MINT_KEY": true, "VULTURE_API_KEYS": true,
	// Provider credentials the backend/broker hold for model routing — all
	// non-VULTURE_-prefixed, so the VULTURE_ rule below does NOT catch them;
	// they MUST be listed exactly or docker would inject the real key into a
	// plugin container (0065 security-review finding).
	"OPENAI_API_KEY": true, "ANTHROPIC_API_KEY": true, "GEMINI_API_KEY": true,
}

var secretSuffixes = []string{"_SECRET", "_TOKEN", "_DSN", "_PASSWORD", "_API_KEY", "_PRIVATE_KEY", "_MINT_KEY"}

// IsBackendSecret HARD-blocks: the exact list, OR any VULTURE_-prefixed,
// secret-shaped name. The VULTURE_ rule auto-covers FUTURE backend secrets
// (0065 §M8) while leaving plugin-namespaced secrets (e.g. SEMGREP_APP_TOKEN)
// to LooksLikeSecret (warn-only, still forwarded).
func IsBackendSecret(name string) bool {
	up := strings.ToUpper(name)
	if secretEnvExact[up] {
		return true
	}
	return strings.HasPrefix(up, "VULTURE_") && LooksLikeSecret(up)
}

// ForwardedEnvNames enumerates the env var names a container plugin
// would receive on launch: every declared runtime.env.required|optional
// name that is not a protected backend secret (0065). Backend secrets
// are already rejected by ValidateManifest, so an installed manifest
// yields the full declared set; callers use this to show the operator
// exactly what will be forwarded before they approve the install.
func ForwardedEnvNames(m *Manifest) []string {
	out := []string{}
	for _, key := range []string{"required", "optional"} {
		for _, name := range envNames(m.Runtime.Env, key) {
			if !IsBackendSecret(name) {
				out = append(out, name)
			}
		}
	}
	return out
}

// LooksLikeSecret reports whether name is credential-shaped by suffix.
func LooksLikeSecret(name string) bool {
	up := strings.ToUpper(name)
	for _, s := range secretSuffixes {
		if strings.HasSuffix(up, s) {
			return true
		}
	}
	return false
}
