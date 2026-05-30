package stagerouter

import (
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// fakeRegistry implements pluginregistry.Registry for unit tests.
type fakeRegistry struct {
	plugins []pluginregistry.Plugin
}

func (f *fakeRegistry) All() []pluginregistry.Plugin { return f.plugins }
func (f *fakeRegistry) Enabled() []pluginregistry.Plugin {
	out := make([]pluginregistry.Plugin, 0, len(f.plugins))
	for _, p := range f.plugins {
		if p.Enabled {
			out = append(out, p)
		}
	}
	return out
}
func (f *fakeRegistry) ByName(name string) (pluginregistry.Plugin, bool) {
	for _, p := range f.plugins {
		if p.Name() == name {
			return p, true
		}
	}
	return pluginregistry.Plugin{}, false
}

func mkPlugin(name string, enabled bool, caps []pluginregistry.Capability) pluginregistry.Plugin {
	return mkPluginWithTier(name, enabled, pluginregistry.TierInTree, caps)
}

func mkPluginWithTier(name string, enabled bool, tier string, caps []pluginregistry.Capability) pluginregistry.Plugin {
	return pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{
				Name:        name,
				Version:     "1.0.0",
				APIVersion:  pluginregistry.APIVersionV1,
				Publisher:   "x",
				Description: "y",
			},
			Trust:        pluginregistry.TrustBlock{Tier: tier},
			Runtime:      pluginregistry.RuntimeBlock{Type: pluginregistry.RuntimeInTree, ModulePath: "x.main:app"},
			Capabilities: caps,
		},
		Source:  "in-tree",
		Enabled: enabled,
	}
}

func mkAgents(name, url string) map[string]config.AgentConfig {
	return map[string]config.AgentConfig{name: {URL: url, Name: name, Type: name}}
}

func TestRoute_NoPlugins_ReturnsEmpty(t *testing.T) {
	r := New(&fakeRegistry{}, nil)
	out, err := r.Route(RouteRequest{Stage: StageScan})
	if err != nil {
		t.Fatalf("Route err: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected zero targets, got %v", out)
	}
}

func TestRoute_DisabledPluginsSkipped(t *testing.T) {
	p := mkPlugin("chaos", false, []pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}}})
	r := New(&fakeRegistry{plugins: []pluginregistry.Plugin{p}}, mkAgents("chaos", "http://x"))
	out, _ := r.Route(RouteRequest{Stage: StageScan})
	if len(out) != 0 {
		t.Errorf("disabled plugin should not route, got %v", out)
	}
}

func TestRoute_ScanIncludesAllScanCapabilities(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPlugin("chaos", true, []pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}}}),
		mkPlugin("owasp", true, []pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}}}),
		mkPlugin("prove", true, []pluginregistry.Capability{{Phase: "prove", Emits: []string{"proof_result"}}}),
	}
	agents := map[string]config.AgentConfig{
		"chaos": {URL: "http://chaos"}, "owasp": {URL: "http://owasp"}, "prove": {URL: "http://prove"},
	}
	r := New(&fakeRegistry{plugins: plugins}, agents)
	out, _ := r.Route(RouteRequest{Stage: StageScan})
	if len(out) != 2 {
		t.Fatalf("expected 2 scan targets, got %d: %+v", len(out), out)
	}
	for _, tt := range out {
		if tt.Phase != "scan" {
			t.Errorf("expected phase=scan, got %s", tt.Phase)
		}
	}
}

func TestRoute_RequestedTypesAllowList(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPlugin("chaos", true, []pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}}}),
		mkPlugin("owasp", true, []pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}}}),
	}
	agents := map[string]config.AgentConfig{
		"chaos": {URL: "http://chaos"}, "owasp": {URL: "http://owasp"},
	}
	r := New(&fakeRegistry{plugins: plugins}, agents)
	out, _ := r.Route(RouteRequest{Stage: StageScan, RequestedTypes: []string{"owasp"}})
	if len(out) != 1 || out[0].PluginName != "owasp" {
		t.Errorf("expected only owasp, got %v", out)
	}
}

func TestRoute_ScanLanguageFilter(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPlugin("py-only", true, []pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}, Languages: []string{"python"}}}),
		mkPlugin("any-lang", true, []pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}}}),
	}
	agents := map[string]config.AgentConfig{
		"py-only": {URL: "http://py"}, "any-lang": {URL: "http://any"},
	}
	r := New(&fakeRegistry{plugins: plugins}, agents)

	// Source is Go-only: py-only is filtered out, any-lang dispatches.
	out, _ := r.Route(RouteRequest{Stage: StageScan, Languages: []string{"go"}})
	if len(out) != 1 || out[0].PluginName != "any-lang" {
		t.Errorf("go-only source: expected only any-lang, got %v", out)
	}

	// Source includes python: both match.
	out, _ = r.Route(RouteRequest{Stage: StageScan, Languages: []string{"python", "go"}})
	if len(out) != 2 {
		t.Errorf("python source: expected both, got %v", out)
	}
}

func TestRoute_DiscoverEmptyTechStacks_DispatchesAll(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPlugin("d1", true, []pluginregistry.Capability{{Phase: "discover", Emits: []string{"discover_result"}, TechStacks: []string{"wordpress"}}}),
		mkPlugin("d2", true, []pluginregistry.Capability{{Phase: "discover", Emits: []string{"discover_result"}}}),
	}
	agents := map[string]config.AgentConfig{
		"d1": {URL: "http://d1"}, "d2": {URL: "http://d2"},
	}
	r := New(&fakeRegistry{plugins: plugins}, agents)
	out, _ := r.Route(RouteRequest{Stage: StageDiscover}) // no tech stacks
	if len(out) != 2 {
		t.Errorf("cold discover should dispatch all, got %v", out)
	}
}

func TestRoute_DiscoverTechStackFilter(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPlugin("d1", true, []pluginregistry.Capability{{Phase: "discover", Emits: []string{"discover_result"}, TechStacks: []string{"wordpress"}}}),
		mkPlugin("d2", true, []pluginregistry.Capability{{Phase: "discover", Emits: []string{"discover_result"}, TechStacks: []string{"express"}}}),
	}
	agents := map[string]config.AgentConfig{
		"d1": {URL: "http://d1"}, "d2": {URL: "http://d2"},
	}
	r := New(&fakeRegistry{plugins: plugins}, agents)
	out, _ := r.Route(RouteRequest{Stage: StageDiscover, TechStacks: []string{"wordpress"}})
	if len(out) != 1 || out[0].PluginName != "d1" {
		t.Errorf("wordpress filter: expected d1, got %v", out)
	}
}

func TestRoute_ProveMatchesByCWE(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPlugin("sqli-prover", true, []pluginregistry.Capability{{
			Phase: "prove", Emits: []string{"proof_result"},
			MatchesCWE: []string{"CWE-89"},
		}}),
		mkPlugin("xss-prover", true, []pluginregistry.Capability{{
			Phase: "prove", Emits: []string{"proof_result"},
			MatchesCWE: []string{"CWE-79"},
		}}),
	}
	agents := map[string]config.AgentConfig{
		"sqli-prover": {URL: "http://s"}, "xss-prover": {URL: "http://x"},
	}
	r := New(&fakeRegistry{plugins: plugins}, agents)
	out, _ := r.Route(RouteRequest{
		Stage: StageProve,
		PriorFindings: []model.PriorFinding{
			{Category: "CWE-89", Title: "SQL injection in login"},
		},
	})
	if len(out) != 1 || out[0].PluginName != "sqli-prover" {
		t.Errorf("CWE-89 only: expected sqli-prover, got %v", out)
	}
	if len(out) == 1 && len(out[0].MatchedFindings) != 1 {
		t.Errorf("expected 1 matched finding, got %v", out[0].MatchedFindings)
	}
}

func TestRoute_ProveMatchesByCheckIDPrefix(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPlugin("owasp-prover", true, []pluginregistry.Capability{{
			Phase: "prove", Emits: []string{"proof_result"},
			MatchesCheckIDPrefix: []string{"owasp."},
		}}),
	}
	r := New(&fakeRegistry{plugins: plugins}, mkAgents("owasp-prover", "http://p"))
	out, _ := r.Route(RouteRequest{
		Stage: StageProve,
		PriorFindings: []model.PriorFinding{
			{Category: "A05-security-misconfig", CheckID: "owasp.misconfig.debug_enabled"},
			{Category: "CWE-89", CheckID: "cwe.sql_injection"},
		},
	})
	if len(out) != 1 {
		t.Fatalf("expected 1 target, got %d", len(out))
	}
	if len(out[0].MatchedFindings) != 1 {
		t.Errorf("expected 1 matched finding (owasp.* only), got %v", out[0].MatchedFindings)
	}
}

func TestRoute_ProveEmptyMatcherFallback(t *testing.T) {
	// In-tree prove agent declares neither matches_cwe nor
	// matches_check_id_prefix — must receive ALL findings.
	plugins := []pluginregistry.Plugin{
		mkPlugin("prove", true, []pluginregistry.Capability{{
			Phase: "prove", Emits: []string{"proof_result"},
		}}),
	}
	r := New(&fakeRegistry{plugins: plugins}, mkAgents("prove", "http://prove"))
	findings := []model.PriorFinding{
		{Category: "CWE-89"}, {Category: "CWE-79"}, {Category: "info"},
	}
	out, _ := r.Route(RouteRequest{Stage: StageProve, PriorFindings: findings})
	if len(out) != 1 {
		t.Fatalf("expected 1 target, got %d", len(out))
	}
	if len(out[0].MatchedFindings) != len(findings) {
		t.Errorf("empty-matcher fallback should pass all findings; got %d/%d",
			len(out[0].MatchedFindings), len(findings))
	}
}

func TestRoute_ProveEmptyPrefixString_UserSupplied_NotDispatched(t *testing.T) {
	// matches_check_id_prefix = [""] must NOT collapse to "matches
	// everything" for non-in-tree tiers. A user-supplied plugin
	// that ships [""] (empty-string prefix) is treated as having
	// no real prefix → falls through to the in-tree-only catch-all
	// → not in-tree → zero dispatch. SH2 data-minimisation holds.
	plugins := []pluginregistry.Plugin{
		mkPluginWithTier("evil", true, pluginregistry.TierUserSupplied,
			[]pluginregistry.Capability{{
				Phase: "prove", Emits: []string{"proof_result"},
				MatchesCheckIDPrefix: []string{""},
			}}),
	}
	r := New(&fakeRegistry{plugins: plugins}, mkAgents("evil", "http://evil"))
	out, _ := r.Route(RouteRequest{
		Stage:         StageProve,
		PriorFindings: []model.PriorFinding{{Category: "CWE-89", CheckID: "owasp.x"}},
	})
	if len(out) != 0 {
		t.Errorf("empty-string prefix on user-supplied plugin must not match: got %v", out)
	}
}

func TestRoute_ProveNoFilters_CommunitySigned_NotDispatched(t *testing.T) {
	// A community-signed prove plugin with NO filters at all must
	// not inherit the in-tree catch-all. SH2 + review BLOCKER #2.
	plugins := []pluginregistry.Plugin{
		mkPluginWithTier("forgot-filters", true, pluginregistry.TierCommunitySigned,
			[]pluginregistry.Capability{{
				Phase: "prove", Emits: []string{"proof_result"},
			}}),
	}
	// Community-signed needs a signature to pass full validation,
	// but the router operates on already-loaded Plugin structs so
	// we skip that here.
	r := New(&fakeRegistry{plugins: plugins}, mkAgents("forgot-filters", "http://x"))
	out, _ := r.Route(RouteRequest{
		Stage:         StageProve,
		PriorFindings: []model.PriorFinding{{Category: "CWE-89"}},
	})
	if len(out) != 0 {
		t.Errorf("non-in-tree catch-all must not dispatch: got %v", out)
	}
}

func TestRoute_ValidateGatedByFlag(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPlugin("v1", true, []pluginregistry.Capability{{Phase: "validate", Emits: []string{"validation_update"}}}),
		mkPlugin("v2", true, []pluginregistry.Capability{{Phase: "validate", Emits: []string{"validation_update"}}}),
	}
	agents := map[string]config.AgentConfig{
		"v1": {URL: "http://v1"}, "v2": {URL: "http://v2"},
	}
	r := New(&fakeRegistry{plugins: plugins}, agents)

	// Default: ValidateEnabled=false → zero dispatch. Honours
	// VULTURE_DISABLE_VALIDATE / L1-L5 gating (feature 0046).
	out, _ := r.Route(RouteRequest{Stage: StageValidate})
	if len(out) != 0 {
		t.Errorf("validate must be gated off by default, got %v", out)
	}

	// Explicit enable → all validate plugins dispatched.
	out, _ = r.Route(RouteRequest{Stage: StageValidate, ValidateEnabled: true})
	if len(out) != 2 {
		t.Errorf("validate stage with ValidateEnabled=true should dispatch all, got %v", out)
	}
}

func TestRoute_MultipleCapabilities_OneTargetEach(t *testing.T) {
	// Review MAJOR #9: a plugin with two scan capabilities for
	// distinct languages produces two DispatchTarget entries when
	// both languages are present in the source. Callers must
	// dedupe by PluginName before launching agent goroutines.
	plugins := []pluginregistry.Plugin{
		mkPlugin("multi", true, []pluginregistry.Capability{
			{Phase: "scan", Emits: []string{"finding"}, Languages: []string{"python"}},
			{Phase: "scan", Emits: []string{"finding"}, Languages: []string{"go"}},
		}),
	}
	r := New(&fakeRegistry{plugins: plugins}, mkAgents("multi", "http://m"))
	out, _ := r.Route(RouteRequest{
		Stage:     StageScan,
		Languages: []string{"python", "go"},
	})
	if len(out) != 2 {
		t.Fatalf("expected 2 targets (one per matching capability), got %d", len(out))
	}
	for _, tt := range out {
		if tt.PluginName != "multi" {
			t.Errorf("expected PluginName=multi, got %q", tt.PluginName)
		}
	}
	// Only python in source → only one of the two capabilities
	// matches.
	out, _ = r.Route(RouteRequest{Stage: StageScan, Languages: []string{"python"}})
	if len(out) != 1 {
		t.Errorf("python-only source: expected 1 target, got %d", len(out))
	}
}

func TestRoute_PluginWithoutURL_Skipped(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPlugin("nowhere", true, []pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}}}),
	}
	// No entry in cfg.Agents, no env var, runtime.type=in-tree (no
	// container port to derive a URL from) → URL resolves to empty.
	r := New(&fakeRegistry{plugins: plugins}, nil)
	out, _ := r.Route(RouteRequest{Stage: StageScan})
	if len(out) != 0 {
		t.Errorf("unreachable plugin should be skipped: %v", out)
	}
}
