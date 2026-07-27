package pluginsupervisor_test

// RED baseline for 0065 Phase 4 — plugin secret containment (F9/F14).
//
// These tests pin the contract from the 0065 plan (§M7 single-source
// denylist, §M8 VULTURE_-secret rule):
//
//   - A manifest that declares a protected BACKEND secret in
//     runtime.env.required (e.g. VULTURE_JWT_SECRET, even when set in the
//     host env) must make buildEnvArgs ERROR — it must NOT emit
//     `-e VULTURE_JWT_SECRET`.
//   - Declared as optional, a protected backend secret is silently OMITTED
//     (warn-only) rather than forwarded.
//   - The VULTURE_-secret rule (§M8) auto-covers FUTURE backend secrets:
//     a not-yet-enumerated VULTURE_FOO_SECRET is blocked the same way.
//   - A plugin's OWN, non-backend, credential-shaped env (SEMGREP_APP_TOKEN)
//     is STILL forwarded (with a warning) — it is not a backend secret.
//
// Current code forwards every declared env unconditionally, and the
// single-source predicate pluginregistry.IsBackendSecret does not exist yet,
// so this file FAILS TO COMPILE (compile-fail RED) and, once the symbol
// exists, the behavioural assertions still fail against un-hardened
// buildEnvArgs. Both are the correct RED state.

import (
	"strings"
	"testing"

	"github.com/vulture/backend/internal/pluginsupervisor"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// envPlugin returns a container plugin declaring the given required/optional
// env var lists. It reuses containerPlugin / defaultOpts from argv_test.go
// (same external test package).
func envPlugin(name string, required, optional []string) pluginregistry.Plugin {
	p := containerPlugin(name)
	req := make([]any, len(required))
	for i, s := range required {
		req[i] = s
	}
	opt := make([]any, len(optional))
	for i, s := range optional {
		opt[i] = s
	}
	p.Manifest.Runtime.Env = map[string]any{
		"required": req,
		"optional": opt,
	}
	return p
}

// TestBuildEnvArgs_RequiredBackendSecret_Rejected_0065 — a required env that
// is a protected backend secret must ERROR even though it is set in the host
// env, and must never be forwarded as `-e VULTURE_JWT_SECRET`.
func TestBuildEnvArgs_RequiredBackendSecret_Rejected_0065(t *testing.T) {
	t.Setenv("VULTURE_JWT_SECRET", "super-secret-signing-key")

	p := envPlugin("evil", []string{"VULTURE_JWT_SECRET"}, nil)
	argv, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err == nil {
		t.Fatalf("required backend secret VULTURE_JWT_SECRET must be rejected; got argv=%v", argv)
	}
	if !strings.Contains(err.Error(), "VULTURE_JWT_SECRET") {
		t.Errorf("error should name the protected env; got %v", err)
	}
	if argvContains(argv, "-e", "VULTURE_JWT_SECRET") {
		t.Errorf("backend secret must NOT be forwarded; argv=%v", argv)
	}
}

// TestBuildEnvArgs_OptionalBackendSecret_Omitted_0065 — declared optional, a
// protected backend secret is silently omitted (warn-only), not forwarded.
func TestBuildEnvArgs_OptionalBackendSecret_Omitted_0065(t *testing.T) {
	t.Setenv("VULTURE_JWT_SECRET", "super-secret-signing-key")

	p := envPlugin("evil", nil, []string{"VULTURE_JWT_SECRET"})
	argv, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err != nil {
		t.Fatalf("optional backend secret must not hard-error; got %v", err)
	}
	if argvHas(argv, "VULTURE_JWT_SECRET") {
		t.Errorf("optional backend secret must be omitted, not forwarded; argv=%v", argv)
	}
}

// TestBuildEnvArgs_FutureVultureSecret_Rejected_0065 — §M8: the VULTURE_-secret
// rule blocks a not-yet-enumerated, credential-shaped VULTURE_ env var.
func TestBuildEnvArgs_FutureVultureSecret_Rejected_0065(t *testing.T) {
	t.Setenv("VULTURE_FOO_SECRET", "future-backend-cred")

	p := envPlugin("evil", []string{"VULTURE_FOO_SECRET"}, nil)
	argv, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err == nil {
		t.Fatalf("future VULTURE_-secret VULTURE_FOO_SECRET must be rejected; got argv=%v", argv)
	}
	if argvContains(argv, "-e", "VULTURE_FOO_SECRET") {
		t.Errorf("future backend secret must NOT be forwarded; argv=%v", argv)
	}
}

// TestBuildEnvArgs_PluginOwnCredential_Forwarded_0065 — a plugin's own,
// non-backend, credential-shaped env is still forwarded (warn-only).
func TestBuildEnvArgs_PluginOwnCredential_Forwarded_0065(t *testing.T) {
	t.Setenv("SEMGREP_APP_TOKEN", "plugin-owned-token")

	p := envPlugin("semgrep", []string{"SEMGREP_APP_TOKEN"}, nil)
	argv, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err != nil {
		t.Fatalf("plugin-owned credential must still be forwarded; got %v", err)
	}
	if !argvContains(argv, "-e", "SEMGREP_APP_TOKEN") {
		t.Errorf("plugin-owned credential SEMGREP_APP_TOKEN must be forwarded; argv=%v", argv)
	}
}

// TestIsBackendSecret_Predicate_0065 — pins the single-source predicate (§M7).
// References the not-yet-existing pluginregistry.IsBackendSecret /
// LooksLikeSecret symbols → compile-fail RED until Phase 4 lands.
func TestIsBackendSecret_Predicate_0065(t *testing.T) {
	backend := []string{
		"VULTURE_JWT_SECRET", "VULTURE_DB_DSN", "VULTURE_DB_PATH",
		"VULTURE_AGENT_TOKEN", "VULTURE_WEBHOOK_SECRET",
		"VULTURE_LLM_BROKER_MINT_KEY", "VULTURE_API_KEYS", "OPENAI_API_KEY",
		"VULTURE_FOO_SECRET", // future, via §M8
	}
	for _, name := range backend {
		if !pluginregistry.IsBackendSecret(name) {
			t.Errorf("IsBackendSecret(%q) = false; want true", name)
		}
	}

	notBackend := []string{"SEMGREP_APP_TOKEN", "PATH", "HOME"}
	for _, name := range notBackend {
		if pluginregistry.IsBackendSecret(name) {
			t.Errorf("IsBackendSecret(%q) = true; want false", name)
		}
	}

	// SEMGREP_APP_TOKEN is credential-shaped (warn-only) but NOT a backend secret.
	if !pluginregistry.LooksLikeSecret("SEMGREP_APP_TOKEN") {
		t.Errorf("LooksLikeSecret(SEMGREP_APP_TOKEN) = false; want true")
	}
	if pluginregistry.LooksLikeSecret("PATH") {
		t.Errorf("LooksLikeSecret(PATH) = true; want false")
	}
}
