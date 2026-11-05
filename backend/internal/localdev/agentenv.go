package localdev

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"strings"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// ensureAgentToken gives the agents and the backend a shared /run secret when
// the operator has not set one. An agent refuses /run without it whenever it is
// set (shared/transport/sse_app.py) and the backend's agent proxy sends it; with
// neither set — the old local default — any local process, or a DNS-rebinding
// page in the browser, could make an agent scan any readable path and stream it
// back. It is set in the launcher's own environment so both sides inherit the
// same value: the backend through Manager.Start, the agents through
// AgentSpawnEnvFromHost, whose keep-set names it. Idempotent: both startBackend
// and startAgents call it, whichever runs first.
func ensureAgentToken() {
	if os.Getenv(pluginregistry.AgentTokenEnv) != "" {
		return
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails since Go 1.24
	_ = os.Setenv(pluginregistry.AgentTokenEnv, hex.EncodeToString(b))
}

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
// VULTURE_AGENT_TOKEN: the agent requires it on every /run the backend sends
// (X-Vulture-Agent-Token, checked in shared/transport/sse_app.py) and presents
// it on its own agent-to-agent /run calls. It is not a credential the agent
// uses against the backend. Filtering it would leave the agent's /run open.
var agentKeepSet = map[string]bool{
	pluginregistry.AgentTokenEnv: true,
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

	return subtractEnv(base, func(name string) bool { return agentEnvDenies(name, p) })
}

// subtractEnv returns a fresh copy of base without the entries whose NAME deny
// matches. deny receives the name upper-cased and trimmed, the form
// pluginregistry.IsBackendSecret uses. Removal has to happen here, before a
// child starts: os/exec resolves a duplicate key to its last occurrence, so
// appending can override a variable but never withhold one.
func subtractEnv(base []string, deny func(string) bool) []string {
	out := make([]string, 0, len(base))
	for _, kv := range base {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || deny(strings.ToUpper(strings.TrimSpace(name))) {
			continue // denied, or not KEY=VALUE (os/exec ignores those anyway)
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

// hostEnv is the package's ONLY sanctioned reader of the process environment
// for a filtered child (agents, and the docker CLI that launches plugins).
// Keeping the os.Environ() call in this one function is what lets the
// forbidigo rule ban it everywhere else — the guardrail 0044 specified and
// never installed. TestHostEnv_SingleSanctionedReader pins it.
func hostEnv() []string {
	return os.Environ() //nolint:forbidigo // the sanctioned call site
}

// AgentSpawnEnvFromHost is the host environment filtered for an agent spawn.
func AgentSpawnEnvFromHost(p SpawnEnvPolicy) []string {
	return AgentSpawnEnv(hostEnv(), p)
}

// PluginCLIEnvFromHost is the host environment filtered for the docker CLI
// that launches plugin containers. A name-only `-e NAME` in its argv copies
// NAME from this environment into the container, so it must hold none of the
// backend's credentials and no injection vector. Unlike the agent filter it has
// no keep-set (VULTURE_AGENT_TOKEN included), no passthrough and no Scrub
// hatch: a plugin's token is added by the supervisor as an explicit overlay.
func PluginCLIEnvFromHost() []string {
	return subtractEnv(hostEnv(), deniedForPluginCLI)
}

// deniedForPluginCLI is the docker CLI's deny rule: every injection vector and
// every backend secret, including the provider keys the agent filter may keep.
func deniedForPluginCLI(name string) bool {
	return isHazardVar(name) || pluginregistry.IsBackendSecret(name)
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
