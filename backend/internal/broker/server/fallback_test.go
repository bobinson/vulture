package server_test

import (
	"net/http"
	"testing"

	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/resilience"
)

// fallbackHarness wires a primary (openai) that can fail and a fallback
// (lmstudio) candidate; the token is scoped for both models.
func fallbackHarness() (*harness, *fakeAdapter) {
	h := newHealthyHarness()
	lm := &fakeAdapter{
		name: "lmstudio",
		resp: &provider.CompletionResponse{
			Model: "qwen3-32b", Provider: "lmstudio", Content: "fallback ok",
			FinishReason: "stop",
			Usage:        provider.Usage{InputTokens: 9, OutputTokens: 4},
			RequestID:    "req-1",
		},
	}
	h.adapters["lmstudio"] = lm
	h.selector.sel = &egress.ModelSelection{
		Model: "gpt-4o",
		Routes: []egress.Candidate{
			{Model: "gpt-4o", Provider: "openai"},
			{Model: "qwen3-32b", Provider: "lmstudio", BaseURL: "https://llm.internal.example/v1"},
		},
	}
	h.verifier.claims.Scope = []string{"scan:gpt-4o", "scan:qwen3-32b"}
	return h, lm
}

// Must-fix: the resolved fallback chain must actually be TRIED. When the
// primary provider is unavailable, the next candidate (re-gated through
// scope + allowlist + SSRF) serves the request (§7/§9).
func TestHandleComplete_FailsOverToFallbackCandidate(t *testing.T) {
	h, lm := fallbackHarness()
	h.openaiFake.err = provider.ErrProviderUnavailable

	rr := doPost(t, h.server(), completePath, testBearer, completeBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fallback chain resolved but never tried); body=%q", rr.Code, rr.Body.String())
	}
	if lm.completeReq == nil {
		t.Fatalf("fallback adapter was never called")
	}
	if lm.completeReq.Model != "qwen3-32b" {
		t.Fatalf("fallback called with model %q, want the candidate's own model qwen3-32b", lm.completeReq.Model)
	}
	// The fallback's route must have been SSRF-validated too (gate re-applied).
	if len(h.ssrf.providers) < 2 || h.ssrf.providers[1] != "lmstudio" {
		t.Fatalf("fallback egress was not re-gated: SSRF providers=%v", h.ssrf.providers)
	}
}

// An open circuit on the primary (provider,model) must fail over to a
// fallback whose OWN breaker is closed — keyed breakers, not one shared.
func TestHandleComplete_CircuitOpenPrimary_FallsOverViaKeyedBreaker(t *testing.T) {
	h, lm := fallbackHarness()
	h.keyedBreakers = map[string]resilience.CircuitBreaker{
		"openai:gpt-4o": &passthroughBreaker{forceErr: resilience.ErrCircuitOpen, state: resilience.StateOpen},
	}

	rr := doPost(t, h.server(), completePath, testBearer, completeBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (open primary circuit must fail over, not fail the request); body=%q", rr.Code, rr.Body.String())
	}
	if lm.completeReq == nil {
		t.Fatalf("fallback adapter was never called after primary circuit-open")
	}
}

// A fallback candidate that fails its own egress gate (provider not
// allowlisted) must be SKIPPED — failover never bypasses the gate. With the
// viable set reduced to the primary alone, the primary's own error is
// surfaced (matching the single-candidate mapping contract).
func TestHandleComplete_FallbackEgressDenied_GateHolds(t *testing.T) {
	h, lm := fallbackHarness()
	h.openaiFake.err = provider.ErrProviderUnavailable
	h.allowlist = &fakeAllowlist{allow: map[string]bool{"openai": true}} // lmstudio NOT allowed

	rr := doPost(t, h.server(), completePath, testBearer, completeBody())
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%q", rr.Code, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "provider_unavailable" {
		t.Fatalf("code = %q, want provider_unavailable", got)
	}
	if lm.completeReq != nil {
		t.Fatalf("gate-denied fallback adapter was called — failover bypassed the egress gate")
	}
}

// When EVERY viable candidate is tried and fails with a failover-class
// error, the request ends all_providers_down (§9).
func TestHandleComplete_AllCandidatesFail_AllProvidersDown(t *testing.T) {
	h, lm := fallbackHarness()
	h.openaiFake.err = provider.ErrProviderUnavailable
	lm.resp = nil
	lm.err = provider.ErrProviderUnavailable

	rr := doPost(t, h.server(), completePath, testBearer, completeBody())
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 all_providers_down; body=%q", rr.Code, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "all_providers_down" {
		t.Fatalf("code = %q, want all_providers_down", got)
	}
	if lm.completeReq == nil {
		t.Fatalf("fallback was never tried before declaring all providers down")
	}
}

// A non-failover error (rate limited) must be returned immediately — the
// loop only fails over on unavailable/circuit-open, never on 429.
func TestHandleComplete_RateLimited_DoesNotFailOver(t *testing.T) {
	h, lm := fallbackHarness()
	h.openaiFake.err = provider.ErrRateLimited

	rr := doPost(t, h.server(), completePath, testBearer, completeBody())
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body=%q", rr.Code, rr.Body.String())
	}
	if lm.completeReq != nil {
		t.Fatalf("429 must not trigger failover, but the fallback adapter was called")
	}
}
