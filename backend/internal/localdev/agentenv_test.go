package localdev

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/vulture/backend/pkg/pluginregistry"
)

// Feature 0073. These tests define the contract of the agent spawn-env filter.
//
// The invariant under test is the one 0044 S5 specified and never enforced:
// a spawned agent must not inherit the backend's credentials or any
// interpreter/dynamic-linker injection vector, while keeping every variable
// the agent legitimately reads.

func envOf(t *testing.T, env []string, key string) (string, bool) {
	t.Helper()
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

func has(t *testing.T, env []string, key string) bool {
	t.Helper()
	_, ok := envOf(t, env, key)
	return ok
}

func scrubPolicy() SpawnEnvPolicy { return SpawnEnvPolicy{Scrub: true} }

// 1. Injection vectors are dropped, asserted through IsScrubbed — the oracle
// that previously had no production subject.
func TestAgentSpawnEnvDropsHazardVectors(t *testing.T) {
	base := []string{
		"LD_PRELOAD=/tmp/evil.so",
		"LD_AUDIT=/tmp/a.so",
		"LD_LIBRARY_PATH=/tmp/lib",
		"DYLD_INSERT_LIBRARIES=/tmp/e.dylib",
		"DYLD_LIBRARY_PATH=/tmp/lib",
		"PYTHONSTARTUP=/tmp/s.py",
		"PYTHONUSERBASE=/tmp/u",
		"PYTHONEXECUTABLE=/tmp/py",
		"PYTHONHOME=/tmp/home",
		"PATH=/usr/bin",
	}
	got := AgentSpawnEnv(base, scrubPolicy())
	if !IsScrubbed(got) {
		t.Fatalf("hazard vector survived the filter: %v", got)
	}
	if !has(t, got, "PATH") {
		t.Error("PATH must survive — the child needs it to exec")
	}
}

// The filter and its oracle must be derived from ONE list, or they drift.
func TestHazardVarsAndIsScrubbedAgree(t *testing.T) {
	for _, name := range agentEnvHazardVars {
		if IsScrubbed([]string{name + "=x"}) {
			t.Errorf("IsScrubbed does not cover hazard var %s — filter and oracle have drifted", name)
		}
	}
}

// 2. Backend credentials are dropped — including the ones a hand-rolled list
// missed (VULTURE_WEBHOOK_SECRET, VULTURE_API_KEYS).
func TestAgentSpawnEnvDropsBackendSecrets(t *testing.T) {
	base := []string{
		"VULTURE_JWT_SECRET=s3cret",
		"VULTURE_DB_DSN=postgres://u:p@h/db",
		"VULTURE_DB_PASSWORD=pw",
		"VULTURE_DB_PATH=/data/v.db",
		"VULTURE_WEBHOOK_SECRET=hmac",
		"VULTURE_API_KEYS=k1,k2",
		"VULTURE_NEON_DSN=postgres://n",
		"VULTURE_LOCAL_DEV_PASSWORD=pw",
		"VULTURE_LLM_BROKER_MINT_KEY=mint",
		"VULTURE_LLM_BROKER_PROVIDER_BASE_URL=http://upstream/v1",
	}
	got := AgentSpawnEnv(base, scrubPolicy())
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if has(t, got, k) {
			t.Errorf("backend-only credential leaked to agent: %s", k)
		}
	}
}

// 3. VULTURE_* CONFIGURATION is retained. This is the 0069 regression guard:
// the old allowlist blocked these, which is what made feature flags
// unreachable in install mode.
func TestAgentSpawnEnvRetainsConfiguration(t *testing.T) {
	base := []string{
		"VULTURE_OBLIGATION_MODE=enforce",
		"VULTURE_CWE_DISABLE_LLM=true",
		"VULTURE_USE_LLM=true",
		"VULTURE_L5_PROMOTION_CLOSURE=true",
		"VULTURE_MAX_FILES=50000",
		"VULTURE_BACKEND_URL=http://localhost:28080",
	}
	got := AgentSpawnEnv(base, scrubPolicy())
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if !has(t, got, k) {
			t.Errorf("configuration var was wrongly filtered: %s", k)
		}
	}
}

// 4. Vars the agent genuinely reads survive — VULTURE_AGENT_TOKEN is in the
// plugin secret vocabulary but agents authenticate with it, so it needs the
// explicit keep-set carve-out.
func TestAgentSpawnEnvRetainsAgentNeededVars(t *testing.T) {
	base := []string{
		"VULTURE_AGENT_TOKEN=tok",
		"VULTURE_LLM_BROKER=on",
		"VULTURE_LLM_BROKER_URL=http://localhost:8090/v1",
	}
	got := AgentSpawnEnv(base, scrubPolicy())
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if !has(t, got, k) {
			t.Errorf("agent-required var was filtered: %s", k)
		}
	}
	if !pluginregistry.IsBackendSecret("VULTURE_AGENT_TOKEN") {
		t.Skip("carve-out no longer needed; IsBackendSecret changed")
	}
}

// 5. Matching is on the exact NAME, case-insensitively — never a substring.
func TestAgentSpawnEnvMatchesExactName(t *testing.T) {
	base := []string{
		"VULTURE_DB_DSN_BACKUP=keepme",
		"MY_VULTURE_JWT_SECRET=keepme",
		"vulture_jwt_secret=drop",
	}
	got := AgentSpawnEnv(base, scrubPolicy())
	if !has(t, got, "VULTURE_DB_DSN_BACKUP") {
		t.Error("substring match wrongly dropped VULTURE_DB_DSN_BACKUP")
	}
	if !has(t, got, "MY_VULTURE_JWT_SECRET") {
		t.Error("suffix match wrongly dropped MY_VULTURE_JWT_SECRET")
	}
	if has(t, got, "vulture_jwt_secret") {
		t.Error("lower-cased secret must still be dropped")
	}
}

// 6. Provider keys: withheld ONLY in broker mode (0064 N1). This is the
// property that "don't append" could never deliver.
func TestAgentSpawnEnvProviderKeys(t *testing.T) {
	base := []string{
		"OPENAI_API_KEY=sk-x",
		"OPENAI_BASE_URL=http://localhost:1234/v1",
		"ANTHROPIC_API_KEY=ak",
		"GEMINI_API_KEY=gk",
	}

	keep := AgentSpawnEnv(base, SpawnEnvPolicy{Scrub: true})
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if !has(t, keep, k) {
			t.Errorf("non-broker mode must keep provider key %s", k)
		}
	}

	withheld := AgentSpawnEnv(base, SpawnEnvPolicy{Scrub: true, WithholdProviderKeys: true})
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if has(t, withheld, k) {
			t.Errorf("broker mode must withhold provider key %s (0064 N1)", k)
		}
	}
}

// 7. The kill switch restores the exact prior behaviour, byte for byte.
func TestAgentSpawnEnvKillSwitchIsExactPassthrough(t *testing.T) {
	base := []string{"VULTURE_JWT_SECRET=s", "LD_PRELOAD=/tmp/e.so", "PATH=/usr/bin"}
	got := AgentSpawnEnv(base, SpawnEnvPolicy{Scrub: false})
	if !slices.Equal(got, base) {
		t.Fatalf("kill switch must be an exact passthrough\n got: %v\nwant: %v", got, base)
	}
}

// 8. Passthrough exempts a named var, but must REFUSE injection vectors: the
// hatch exists for configuration, not for re-enabling code injection.
func TestAgentSpawnEnvPassthroughRefusesHazards(t *testing.T) {
	base := []string{"VULTURE_JWT_SECRET=s", "LD_PRELOAD=/tmp/e.so"}
	p := SpawnEnvPolicy{
		Scrub:       true,
		Passthrough: map[string]bool{"VULTURE_JWT_SECRET": true, "LD_PRELOAD": true},
	}
	got := AgentSpawnEnv(base, p)
	if !has(t, got, "VULTURE_JWT_SECRET") {
		t.Error("passthrough must exempt a named secret when the operator opts in")
	}
	if has(t, got, "LD_PRELOAD") {
		t.Error("passthrough must NEVER re-admit an injection vector")
	}
}

// 9. The result must be freshly allocated: startAgents concatenates onto this
// base once per agent, and a shared backing array would let one agent's
// entries overwrite another's.
func TestAgentSpawnEnvReturnsFreshSlice(t *testing.T) {
	base := []string{"A=1", "B=2", "PATH=/usr/bin"}
	got := AgentSpawnEnv(base, scrubPolicy())
	if len(got) > 0 {
		got[0] = "MUTATED=1"
	}
	if base[0] != "A=1" {
		t.Fatal("AgentSpawnEnv aliased its input — callers can corrupt each other")
	}
	full := append(got, "X=1") //nolint:gocritic // deliberately exercising append on the result
	_ = full
	if cap(got) != len(got) {
		t.Log("note: result has spare capacity; callers must use slices.Concat, not append")
	}
}

// 10. Reconciliation with the repo's single source of truth (0065 §M7). This
// is the test that fails when the two vocabularies rot apart.
func TestAgentSpawnEnvReconcilesWithBackendSecretRule(t *testing.T) {
	corpus := []string{
		"VULTURE_JWT_SECRET", "VULTURE_DB_DSN", "VULTURE_DB_PATH",
		"VULTURE_WEBHOOK_SECRET", "VULTURE_API_KEYS", "VULTURE_LLM_BROKER_MINT_KEY",
		"VULTURE_DB_PASSWORD", "VULTURE_NEON_DSN", "VULTURE_LOCAL_DEV_PASSWORD",
		"VULTURE_AGENT_TOKEN",
	}
	for _, name := range corpus {
		if !pluginregistry.IsBackendSecret(name) {
			continue
		}
		got := AgentSpawnEnv([]string{name + "=v"}, scrubPolicy())
		filtered := !has(t, got, name)
		_, excepted := agentKeepSet[strings.ToUpper(name)]
		if !filtered && !excepted {
			t.Errorf("%s is a backend secret but is neither filtered nor in agentKeepSet", name)
		}
		if filtered && excepted {
			t.Errorf("%s is in agentKeepSet but was filtered anyway", name)
		}
	}
}

// 11. Policy reads the documented env contract (default-on).
func TestSpawnEnvPolicyFromEnv(t *testing.T) {
	t.Setenv("VULTURE_AGENT_ENV_SCRUB", "")
	t.Setenv("VULTURE_AGENT_ENV_PASSTHROUGH", "")
	if p := SpawnEnvPolicyFromEnv(false); !p.Scrub {
		t.Error("scrub must default to ON")
	}
	t.Setenv("VULTURE_AGENT_ENV_SCRUB", "false")
	if p := SpawnEnvPolicyFromEnv(false); p.Scrub {
		t.Error("VULTURE_AGENT_ENV_SCRUB=false must disable scrubbing")
	}
	t.Setenv("VULTURE_AGENT_ENV_SCRUB", "true")
	t.Setenv("VULTURE_AGENT_ENV_PASSTHROUGH", "VULTURE_JWT_SECRET, ld_preload ")
	p := SpawnEnvPolicyFromEnv(true)
	if !p.Passthrough["VULTURE_JWT_SECRET"] {
		t.Error("passthrough list must be parsed and upper-cased")
	}
	if !p.WithholdProviderKeys {
		t.Error("withholdProviderKeys argument must be honoured")
	}
}

// 12. AgentSpawnEnvFromHost is the single sanctioned os.Environ() reader.
func TestAgentSpawnEnvFromHostFiltersRealEnvironment(t *testing.T) {
	t.Setenv("VULTURE_JWT_SECRET", "live-secret")
	t.Setenv("VULTURE_OBLIGATION_MODE", "enforce")
	got := AgentSpawnEnvFromHost(scrubPolicy())
	if has(t, got, "VULTURE_JWT_SECRET") {
		t.Error("host secret leaked through AgentSpawnEnvFromHost")
	}
	if !has(t, got, "VULTURE_OBLIGATION_MODE") {
		t.Error("host configuration must survive")
	}
	if len(got) == 0 || !has(t, got, "PATH") && os.Getenv("PATH") != "" {
		t.Error("expected a populated environment")
	}
}
