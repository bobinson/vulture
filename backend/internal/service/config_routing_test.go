package service

import (
	"encoding/json"
	"testing"
)

// Feature 0081 business contract: an audit config reaches the agents it is
// addressed to.
//
// `extractAgentConfig` routed ONLY by agent type and returned `{}` for anything
// else, silently. Four shipped things depended on the flat form and got nothing:
//
//	CLI --validate-llm  {"validate":{"llm":true}}  -> {}   L5 judge never enabled
//	CLI --llm-tier3     {"llm_tier3":true}         -> {}   sweep never widened
//	pipeline discover   {"target_url":...}         -> {}   target URL never sent
//	pipeline prove      {"staging_url":...}        -> {}   staging URL never sent
//
// The flat form is an internal convention, not a client mistake: Vulture's own
// GetStageAuditConfig is its largest producer. That is why the fix merges rather
// than rejects — an earlier draft proposed a 400 and would have broken every
// pipeline stage.

func cfgFor(t *testing.T, raw, agent string) map[string]any {
	t.Helper()
	got := extractAgentConfig(parseAuditConfigMap(json.RawMessage(raw)), agent)
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("agent config is not an object: %s (%v)", string(got), err)
	}
	return m
}

// T1 — the reported case. A cross-cutting key must reach every agent.
func TestFlatKeyReachesEveryAgent(t *testing.T) {
	for _, agent := range []string{"cwe", "xss", "chaos", "soc2", "ssdf", "asvs"} {
		m := cfgFor(t, `{"use_llm":false}`, agent)
		v, ok := m["use_llm"]
		if !ok {
			t.Errorf("agent %s never received use_llm — this is the reported bug", agent)
			continue
		}
		if v != false {
			t.Errorf("agent %s got use_llm=%v, want false", agent, v)
		}
	}
}

// T2 — pipeline delivery. Both stages send FLAT keys today and receive nothing.
func TestPipelineStageConfigReachesItsAgent(t *testing.T) {
	d := cfgFor(t, `{"target_url":"http://x","scan_findings":[1,2]}`, "discover")
	if d["target_url"] != "http://x" {
		t.Errorf("discover never received target_url: %v", d)
	}
	if _, ok := d["scan_findings"]; !ok {
		t.Errorf("discover never received scan_findings: %v", d)
	}
	p := cfgFor(t, `{"staging_url":"http://y"}`, "prove")
	if p["staging_url"] != "http://y" {
		t.Errorf("prove never received staging_url: %v", p)
	}
}

// T3 — the two dead CLI flags.
func TestDeadCliFlagsNowReachAgents(t *testing.T) {
	v := cfgFor(t, `{"validate":{"llm":true}}`, "cwe")
	blob, ok := v["validate"].(map[string]any)
	if !ok || blob["llm"] != true {
		t.Errorf("--validate-llm still does not reach the agent: %v", v)
	}
	t3 := cfgFor(t, `{"llm_tier3":true}`, "cwe")
	if t3["llm_tier3"] != true {
		t.Errorf("--llm-tier3 still does not reach the agent: %v", t3)
	}
}

// T4 — precedence. A per-agent value overrides the global one; a global default
// with a per-agent override is the useful shape and the reverse never is.
func TestPerAgentOverridesFlat(t *testing.T) {
	raw := `{"llm_tier3":true,"cwe":{"llm_tier3":false}}`
	if got := cfgFor(t, raw, "cwe")["llm_tier3"]; got != false {
		t.Errorf("cwe must take its per-agent override, got %v", got)
	}
	if got := cfgFor(t, raw, "xss")["llm_tier3"]; got != true {
		t.Errorf("xss must take the flat default, got %v", got)
	}
}

// T5 — regression. The per-agent form must be untouched, and must NOT leak.
func TestPerAgentFormDoesNotLeak(t *testing.T) {
	raw := `{"prove":{"staging_url":"x"}}`
	if got := cfgFor(t, raw, "prove")["staging_url"]; got != "x" {
		t.Errorf("prove lost its own config: %v", got)
	}
	if m := cfgFor(t, raw, "cwe"); len(m) != 0 {
		t.Errorf("prove's config leaked into cwe: %v — prove and discover are "+
			"agent types and must never be treated as cross-cutting keys", m)
	}
}

// T6 — NON-VACUITY. With the switch off every case above reverts to `{}`, which
// proves these tests observe the merge and not something incidental.
func TestRollbackRestoresPerAgentOnlyRouting(t *testing.T) {
	t.Setenv("VULTURE_AUDIT_CONFIG_MERGE", "false")
	for _, raw := range []string{
		`{"use_llm":false}`, `{"validate":{"llm":true}}`,
		`{"llm_tier3":true}`, `{"target_url":"http://x"}`,
	} {
		if m := cfgFor(t, raw, "cwe"); len(m) != 0 {
			t.Errorf("with the merge off, %s must yield {} for cwe, got %v", raw, m)
		}
	}
	// the per-agent form still works with the merge off
	if got := cfgFor(t, `{"cwe":{"a":1}}`, "cwe")["a"]; got != float64(1) {
		t.Errorf("per-agent routing must survive the rollback, got %v", got)
	}
}

// T7 — the agent-type set. This is the trap that decides T5: ScanAgentTypes()
// EXCLUDES prove and discover because they are pipeline stages rather than
// scanners, so sourcing from it would treat `{"prove":{...}}` as a flat key and
// merge it into every agent.
//
// Note on plugins: `knownAgentTypes` reads the LIVE plugin registry, so an
// installed plugin's name is an agent type. A unit test has no plugin installed,
// so that half cannot be asserted here — and the behaviour is correct either
// way: an uninstalled plugin's block is not agent config, and merging it is
// harmless because no agent validates its config.
func TestKnownAgentTypesIncludesPipelineStages(t *testing.T) {
	known := knownAgentTypes()
	for _, want := range []string{"prove", "discover"} {
		if !known[want] {
			t.Errorf("%q must be a known agent type, or its config block would be "+
				"merged into every agent (see TestPerAgentFormDoesNotLeak)", want)
		}
	}
	for _, want := range []string{"cwe", "xss", "chaos", "soc2", "ssdf", "asvs", "owasp"} {
		if !known[want] {
			t.Errorf("%q missing from the agent-type set", want)
		}
	}
	if len(known) < 8 {
		t.Fatalf("only %d agent types resolved — the set looks unpopulated, which "+
			"would make every per-agent block leak", len(known))
	}
}

// T8 — an empty or absent config must stay an empty object, not become null.
func TestEmptyConfigStaysAnEmptyObject(t *testing.T) {
	for _, raw := range []string{`{}`, `null`, ``} {
		got := extractAgentConfig(parseAuditConfigMap(json.RawMessage(raw)), "cwe")
		if string(got) != "{}" {
			t.Errorf("config %q produced %q, want {}", raw, string(got))
		}
	}
}
