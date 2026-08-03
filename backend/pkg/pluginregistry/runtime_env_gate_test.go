package pluginregistry

import (
	"strings"
	"testing"
)

// runtimeEnv builds a RuntimeBlock.Env map with the given required/optional
// name lists (the []string shape used by programmatically-built manifests).
func runtimeEnv(required, optional []string) map[string]any {
	return map[string]any{"required": required, "optional": optional}
}

// TestValidateRuntimeEnvBlock is the install-time gate (0065 §4.t2). Audit
// finding #7: previously untested — the Phase-4 tests built Plugins directly and
// bypassed ValidateManifest, so a regression dropping this check would ship.
func TestValidateRuntimeEnvBlock(t *testing.T) {
	// A backend secret declared as required is rejected at install.
	err := validateRuntimeEnvBlock(&RuntimeBlock{Env: runtimeEnv([]string{"VULTURE_JWT_SECRET"}, nil)})
	if err == nil || !strings.Contains(err.Error(), "VULTURE_JWT_SECRET") {
		t.Fatalf("required backend secret must be rejected, got %v", err)
	}
	// A future VULTURE_-prefixed secret-shaped name is rejected too (§M8).
	if err := validateRuntimeEnvBlock(&RuntimeBlock{Env: runtimeEnv(nil, []string{"VULTURE_FOO_TOKEN"})}); err == nil {
		t.Fatal("VULTURE_-prefixed secret-shaped optional env must be rejected")
	}
	// A non-VULTURE provider key in the exact denylist is rejected (S3).
	if err := validateRuntimeEnvBlock(&RuntimeBlock{Env: runtimeEnv([]string{"ANTHROPIC_API_KEY"}, nil)}); err == nil {
		t.Fatal("ANTHROPIC_API_KEY must be rejected")
	}
	// Benign plugin-namespaced env passes.
	if err := validateRuntimeEnvBlock(&RuntimeBlock{Env: runtimeEnv([]string{"SEMGREP_APP_TOKEN"}, []string{"PLUGIN_FOO"})}); err != nil {
		t.Fatalf("plugin-namespaced env must pass, got %v", err)
	}
	// Empty block passes.
	if err := validateRuntimeEnvBlock(&RuntimeBlock{}); err != nil {
		t.Fatalf("empty runtime env must pass, got %v", err)
	}
}

// TestForwardedEnvNames is the install-ack enumeration (0065 §4.t3). Audit
// finding #8: previously unreferenced by any test. Backend secrets must be
// excluded from the forwarded set; plugin-namespaced names retained.
func TestForwardedEnvNames(t *testing.T) {
	m := &Manifest{Runtime: RuntimeBlock{Env: runtimeEnv(
		[]string{"SEMGREP_APP_TOKEN"},                // plugin's own → forwarded
		[]string{"VULTURE_JWT_SECRET", "PLUGIN_FOO"}, // backend secret dropped; PLUGIN_FOO kept
	)}}
	got := ForwardedEnvNames(m)
	has := func(n string) bool {
		for _, g := range got {
			if g == n {
				return true
			}
		}
		return false
	}
	if !has("SEMGREP_APP_TOKEN") || !has("PLUGIN_FOO") {
		t.Errorf("plugin-namespaced env must be forwarded, got %v", got)
	}
	if has("VULTURE_JWT_SECRET") {
		t.Errorf("backend secret must NOT be enumerated as forwarded, got %v", got)
	}
}
