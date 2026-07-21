package server_test

import (
	"net/http"
	"testing"

	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/provider"
)

// Must-fix: egress routing must come from the RESOLVED SELECTION (per-model
// provider + tenant base_url), not a hardcoded provider (§7/§11). The
// allowlist and SSRF gates must be applied to the selected provider's route,
// and the call must reach that provider's adapter.
func TestHandleComplete_RoutesProviderFromSelection(t *testing.T) {
	h := newHealthyHarness()
	lm := &fakeAdapter{
		name: "lmstudio",
		resp: &provider.CompletionResponse{
			Model: "qwen3-32b", Provider: "lmstudio", Content: "ok",
			FinishReason: "stop",
			Usage:        provider.Usage{InputTokens: 10, OutputTokens: 5},
			RequestID:    "req-1",
		},
	}
	h.adapters["lmstudio"] = lm
	// ONLY lmstudio is allowlisted: a hardcoded-"openai" egress check fails here.
	h.allowlist = &fakeAllowlist{allow: map[string]bool{"lmstudio": true}}
	h.selector.sel = &egress.ModelSelection{
		Model: "qwen3-32b",
		Routes: []egress.Candidate{
			{Model: "qwen3-32b", Provider: "lmstudio", BaseURL: "https://llm.internal.example/v1"},
		},
	}
	h.verifier.claims.Scope = []string{"scan:qwen3-32b"}
	body := completeBody()
	body["model_hint"] = "qwen3-32b"

	rr := doPost(t, h.server(), completePath, testBearer, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (routing hardcodes a provider instead of using the selection); body=%q", rr.Code, rr.Body.String())
	}
	if lm.completeReq == nil {
		t.Fatalf("selected provider's adapter (lmstudio) was never called")
	}
	if h.openaiFake.completeReq != nil {
		t.Fatalf("default openai adapter was called despite the selection routing to lmstudio")
	}
	if len(h.ssrf.providers) == 0 || h.ssrf.providers[0] != "lmstudio" {
		t.Fatalf("SSRF validated provider %v, want [lmstudio ...]", h.ssrf.providers)
	}
	if len(h.ssrf.baseURLs) == 0 || h.ssrf.baseURLs[0] != "https://llm.internal.example/v1" {
		t.Fatalf("SSRF validated base URL %v, want the tenant route URL", h.ssrf.baseURLs)
	}
}

// Default routing must be preserved: a selection without explicit routes
// egresses via the default provider and its canonical endpoint.
func TestHandleComplete_DefaultRouteStaysOpenAI(t *testing.T) {
	h := newHealthyHarness()
	rr := doPost(t, h.server(), completePath, testBearer, completeBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	if len(h.ssrf.providers) == 0 || h.ssrf.providers[0] != "openai" {
		t.Fatalf("SSRF validated provider %v, want [openai]", h.ssrf.providers)
	}
	if len(h.ssrf.baseURLs) == 0 || h.ssrf.baseURLs[0] != "https://api.openai.com/v1" {
		t.Fatalf("SSRF validated base URL %v, want the canonical default", h.ssrf.baseURLs)
	}
}

// N1: the broker resolves the provider API key into the adapter credentials —
// keys live only in the broker, and the adapter must receive the key for the
// ROUTED provider.
func TestHandleComplete_AdapterReceivesProviderKey(t *testing.T) {
	h := newHealthyHarness()
	h.keys = provider.StaticKeys{"openai": "sk-test-123", "lmstudio": "unused"}
	rr := doPost(t, h.server(), completePath, testBearer, completeBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	if got := h.openaiFake.seenCreds.APIKey; got != "sk-test-123" {
		t.Fatalf("adapter credentials APIKey = %q, want the broker-resolved provider key", got)
	}
}
