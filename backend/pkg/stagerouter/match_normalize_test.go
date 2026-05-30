package stagerouter

// RED-phase test for feature 0050 AC 9: router prove-stage integration
// with the CWE normalisation Layer.
//
// References:
//   - cwe.Layer interface (internal/cwe/layer.go — does not exist yet)
//   - NewWithLayer constructor (router.go — does not exist yet)
//   - matchPriorFindings 3-arg signature (match.go — currently 2-arg)
//
// This file MUST fail to compile until the GREEN phase ships:
//   1. internal/cwe/layer.go with the Layer interface.
//   2. stagerouter.NewWithLayer(registry, agents, layer cwe.Layer) Router.
//   3. matchPriorFindings updated to take a third `layer cwe.Layer` arg.
// Compilation failure is the correct RED state.

import (
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/cwe"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// fakeLayer returns canned answers for one specific input triple
// and the empty string for everything else. Lets the test verify
// the layer is consulted (rather than the legacy exact-string match
// against Category).
type fakeLayer struct {
	wantAgent    string
	wantCategory string
	wantCheckID  string
	returns      string
}

func (f *fakeLayer) Normalize(agentType, category, checkID string) string {
	if agentType == f.wantAgent && category == f.wantCategory && (f.wantCheckID == "" || checkID == f.wantCheckID) {
		return f.returns
	}
	return ""
}

// AC 9: a prove-stage plugin declaring matches_cwe = ["CWE-284"]
// must dispatch on a prior finding with Category = "A01-access-control"
// (NOT canonical CWE) once the Layer normalises it to CWE-284.
//
// Without the Layer (or with the passthrough), the legacy exact-string
// match against Category would fail to match — that's the bug 0050
// solves. With the Layer, dispatch fires and MatchedFindings contains
// the finding.
func TestRoute_ProveStage_UsesLayerNormalization_AC9(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPlugin("access-prover", true, []pluginregistry.Capability{{
			Phase:      "prove",
			Emits:      []string{"proof_result"},
			MatchesCWE: []string{"CWE-284"},
		}}),
	}
	agents := map[string]config.AgentConfig{
		"access-prover": {URL: "http://access-prover"},
	}

	// Layer translates ("owasp", "A01-access-control", _) → "CWE-284".
	// Every other input returns empty (forces the test to fail if the
	// router routes for the wrong reason).
	layer := &fakeLayer{
		wantAgent:    "owasp",
		wantCategory: "A01-access-control",
		returns:      "CWE-284",
	}

	// NewWithLayer is the new 3-arg constructor introduced by 0050.
	// Does not exist yet → compile error in RED.
	r := NewWithLayer(&fakeRegistry{plugins: plugins}, agents, layer)

	priorFinding := model.PriorFinding{
		AgentType: "owasp",
		Category:  "A01-access-control", // NOT CWE-NNN form
		Title:     "broken access control on /admin",
	}
	out, err := r.Route(RouteRequest{
		Stage:         StageProve,
		PriorFindings: []model.PriorFinding{priorFinding},
	})
	if err != nil {
		t.Fatalf("Route err: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 dispatch target (layer normalises A01 → CWE-284 → matches), got %d: %+v", len(out), out)
	}
	if out[0].PluginName != "access-prover" {
		t.Errorf("expected PluginName=access-prover, got %q", out[0].PluginName)
	}
	if len(out[0].MatchedFindings) != 1 {
		t.Fatalf("expected 1 MatchedFindings (the normalised owasp finding), got %d", len(out[0].MatchedFindings))
	}
	if out[0].MatchedFindings[0].Category != "A01-access-control" {
		// The router must pass through the ORIGINAL category — it
		// only uses the layer for matching, not for mutation. LLD
		// §"Goal": "without mutating the original Category".
		t.Errorf("MatchedFindings[0].Category = %q; want A01-access-control (original Category must be preserved, not rewritten)", out[0].MatchedFindings[0].Category)
	}
}

// AC 9 negative: a finding whose AgentType differs from what the
// layer matches must NOT dispatch. This protects against per-plugin
// scope bleed.
func TestRoute_ProveStage_LayerScopedByAgentType_AC9(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPlugin("access-prover", true, []pluginregistry.Capability{{
			Phase:      "prove",
			Emits:      []string{"proof_result"},
			MatchesCWE: []string{"CWE-284"},
		}}),
	}
	agents := map[string]config.AgentConfig{
		"access-prover": {URL: "http://access-prover"},
	}

	// Layer only fires for AgentType="owasp". A finding emitted by
	// "semgrep" with the same category must not be normalised by it.
	layer := &fakeLayer{
		wantAgent:    "owasp",
		wantCategory: "A01-access-control",
		returns:      "CWE-284",
	}

	r := NewWithLayer(&fakeRegistry{plugins: plugins}, agents, layer)
	out, _ := r.Route(RouteRequest{
		Stage: StageProve,
		PriorFindings: []model.PriorFinding{{
			AgentType: "semgrep", // not "owasp" — layer returns ""
			Category:  "A01-access-control",
		}},
	})
	if len(out) != 0 {
		t.Errorf("layer scoped by AgentType: semgrep-emitted finding must not dispatch to owasp-only CWE-284 prover; got %d targets", len(out))
	}
}

// AC 10 (no-regression sanity): NewWithLayer with the passthroughLayer
// (which Normalize=="" for every input) must dispatch identically to
// the 0049 behaviour — i.e., legacy exact-string match against
// Category. This guarantees `NewWithLayer(reg, agents, passthroughLayer{})`
// is bit-identical to `New(reg, agents)`.
//
// The test feeds a CWE-89-categorised finding and asserts the
// sqli-prover (matches_cwe=[CWE-89]) still receives it — proving the
// legacy fallback path still works after the layer hook is added.
func TestRoute_ProveStage_NilLayerEquivalentToLegacy_AC10(t *testing.T) {
	plugins := []pluginregistry.Plugin{
		mkPlugin("sqli-prover", true, []pluginregistry.Capability{{
			Phase:      "prove",
			Emits:      []string{"proof_result"},
			MatchesCWE: []string{"CWE-89"},
		}}),
	}
	agents := map[string]config.AgentConfig{"sqli-prover": {URL: "http://s"}}

	// passthroughLayer: returns "" for every input. Router must fall
	// back to f.Category — same as 0049.
	pass := cwe.NewFromMaps(nil, nil, nil, nil)
	r := NewWithLayer(&fakeRegistry{plugins: plugins}, agents, pass)

	out, _ := r.Route(RouteRequest{
		Stage: StageProve,
		PriorFindings: []model.PriorFinding{
			{Category: "CWE-89", Title: "SQLi in login"},
		},
	})
	if len(out) != 1 || out[0].PluginName != "sqli-prover" {
		t.Fatalf("passthrough layer must not regress 0049 behaviour: expected sqli-prover, got %+v", out)
	}
	if len(out[0].MatchedFindings) != 1 {
		t.Errorf("legacy exact-string match path failed: expected 1 MatchedFindings, got %d", len(out[0].MatchedFindings))
	}
}
