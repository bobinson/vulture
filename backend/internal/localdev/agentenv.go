package localdev

import (
	"log"
	"os"
	"strings"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// Feature 0073 — the agent spawn-env filter.
//
// Feature 0044 specified S5 ("agent subprocesses run with a scrubbed
// environment") and required that every exec.Cmd.Env assignment go through a
// builder. The builder shipped with no caller, so for three months every
// spawned agent inherited the backend's whole environment — JWT signing key,
// Postgres DSN and webhook HMAC key included.
//
// The reason a fix has to live HERE, at the spawn boundary, is that
// `append(os.Environ(), extra...)` makes appending a valid override but leaves
// no way to express a removal: os/exec resolves duplicate keys to the last
// occurrence, so a variable the launcher declines to add is still inherited.
// Withholding must therefore be subtractive, which is what this file does.

// agentEnvHazardVars are interpreter / dynamic-linker injection vectors. Each
// one lets whatever set it execute code inside the agent before its first
// statement runs, so none may ever reach a spawned agent — not even via the
// operator passthrough hatch.
//
// This slice is the single source of truth: IsScrubbed derives its banned set
// from it, so the filter and its own test oracle cannot drift apart.
var agentEnvHazardVars = []string{
	"LD_PRELOAD",
	"LD_AUDIT",
	"LD_LIBRARY_PATH",
	"DYLD_INSERT_LIBRARIES",
	"DYLD_LIBRARY_PATH",
	"PYTHONSTARTUP",
	"PYTHONUSERBASE",
	"PYTHONEXECUTABLE",
	"PYTHONHOME",
}

// agentKeepSet names variables that pluginregistry.IsBackendSecret classifies
// as backend credentials but that AGENTS legitimately read. This is the one
// place the plugin vocabulary and the agent vocabulary differ, and it is
// deliberately tiny.
//
// VULTURE_AGENT_TOKEN: the agent authenticates to the backend with it
// (shared/transport/sse_app.py). Filtering it breaks every agent callback.
var agentKeepSet = map[string]bool{
	"VULTURE_AGENT_TOKEN": true,
}

// agentDeniedConfig are backend-only variables the secret RULE cannot catch
// because they are not secret-SHAPED, yet must not reach an agent.
//
// VULTURE_LLM_BROKER_PROVIDER_BASE_URL is the real upstream gateway the broker
// exists to be the sole holder of; handing it to an agent defeats the point of
// routing through the broker at all.
var agentDeniedConfig = map[string]bool{
	"VULTURE_LLM_BROKER_PROVIDER_BASE_URL": true,
}

// providerKeyVars are withheld only when the broker is on (0064 N1): the
// broker holds the credential and mints a per-run token instead.
var providerKeyVars = map[string]bool{
	"OPENAI_API_KEY":    true,
	"OPENAI_BASE_URL":   true,
	"ANTHROPIC_API_KEY": true,
	"GEMINI_API_KEY":    true,
}

// SpawnEnvPolicy is the resolved filtering policy for one spawn.
type SpawnEnvPolicy struct {
	// Scrub false restores pre-0073 full inheritance (rollback hatch).
	Scrub bool
	// WithholdProviderKeys drops the provider credentials (broker mode).
	WithholdProviderKeys bool
	// Passthrough exempts operator-named variables. Upper-cased keys.
	// Injection vectors are refused regardless of what is listed here.
	Passthrough map[string]bool
}

// SpawnEnvPolicyFromEnv resolves the policy from the documented environment
// contract. withholdProviderKeys comes from the caller because it is derived
// from the broker wiring, not read directly.
func SpawnEnvPolicyFromEnv(withholdProviderKeys bool) SpawnEnvPolicy {
	p := SpawnEnvPolicy{
		Scrub:                true,
		WithholdProviderKeys: withholdProviderKeys,
		Passthrough:          map[string]bool{},
	}
	// Default-on: only an explicitly falsy value disables the control.
	if v := strings.TrimSpace(os.Getenv("VULTURE_AGENT_ENV_SCRUB")); v != "" {
		p.Scrub = config.EnvTruthy("VULTURE_AGENT_ENV_SCRUB")
	}
	if !p.Scrub {
		log.Printf("0073 WARNING: VULTURE_AGENT_ENV_SCRUB=false — spawned agents inherit " +
			"the backend's full environment, including credentials")
	}
	raw := strings.TrimSpace(os.Getenv("VULTURE_AGENT_ENV_PASSTHROUGH"))
	if raw == "" {
		return p
	}
	var admitted []string
	for _, name := range strings.Split(raw, ",") {
		name = strings.ToUpper(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if isHazardVar(name) {
			log.Printf("0073 WARNING: VULTURE_AGENT_ENV_PASSTHROUGH lists %s, an injection "+
				"vector — refused", name)
			continue
		}
		p.Passthrough[name] = true
		admitted = append(admitted, name)
	}
	if len(admitted) > 0 {
		log.Printf("0073 WARNING: VULTURE_AGENT_ENV_PASSTHROUGH exempts %s from agent env filtering",
			strings.Join(admitted, ", "))
	}
	return p
}

func isHazardVar(upperName string) bool {
	for _, h := range agentEnvHazardVars {
		if upperName == h {
			return true
		}
	}
	return false
}

// AgentSpawnEnv returns base minus everything a spawned agent must not see.
//
// Matching is on the exact variable NAME, upper-cased (aligning with
// pluginregistry.IsBackendSecret) — never a substring, so VULTURE_DB_DSN_BACKUP
// is unaffected by the VULTURE_DB_DSN rule.
//
// The result is always a freshly allocated slice: startAgents concatenates onto
// this base once per agent, and a shared backing array would let one agent's
// entries overwrite another's.
func AgentSpawnEnv(base []string, p SpawnEnvPolicy) []string {
	if !p.Scrub {
		// Exact passthrough — the rollback hatch must be byte-for-byte the
		// pre-0073 behaviour, but still a copy (see allocation contract).
		out := make([]string, len(base))
		copy(out, base)
		return out
	}

	out := make([]string, 0, len(base))
	for _, kv := range base {
		name, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue // not a KEY=VALUE entry; os/exec ignores these anyway
		}
		if agentEnvDenies(strings.ToUpper(strings.TrimSpace(name)), p) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// agentEnvDenies is the whole policy, in precedence order.
func agentEnvDenies(name string, p SpawnEnvPolicy) bool {
	// Injection vectors are unconditional — the passthrough hatch cannot
	// re-admit them, or the hatch would become the vulnerability.
	if isHazardVar(name) {
		return true
	}
	if p.Passthrough[name] {
		return false
	}
	if agentKeepSet[name] {
		return false
	}
	if agentDeniedConfig[name] {
		return true
	}
	// Provider credentials are governed ONLY by the broker policy, and must
	// short-circuit the rule below. IsBackendSecret lists them as
	// never-forwardable, which is right for a PLUGIN container but wrong for
	// an agent: with the broker off (the Mode A default) the agent is the
	// component that talks to the provider, so withholding the key here would
	// break every direct LM Studio / OpenAI / Ollama run.
	if providerKeyVars[name] {
		return p.WithholdProviderKeys
	}
	// The repo's single source of truth for backend credentials (0065 §M7).
	// Rule-based, so it auto-covers secrets added by future features.
	return pluginregistry.IsBackendSecret(name)
}

// AgentSpawnEnvFromHost is the ONLY sanctioned reader of the process
// environment for agent spawning. Keeping the os.Environ() call in this one
// file is what lets the forbidigo rule ban it everywhere else — the guardrail
// 0044 specified (plan:1129) and never installed.
func AgentSpawnEnvFromHost(p SpawnEnvPolicy) []string {
	return AgentSpawnEnv(os.Environ(), p) //nolint:forbidigo // the sanctioned call site
}

// IsScrubbed reports whether the given env list omits every hazardous
// inheritance key. Retained from 0044 as the invariant oracle, now derived
// from agentEnvHazardVars so it can never disagree with the filter.
func IsScrubbed(env []string) bool {
	for _, e := range env {
		name, _, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		if isHazardVar(strings.ToUpper(strings.TrimSpace(name))) {
			return false
		}
	}
	return true
}
