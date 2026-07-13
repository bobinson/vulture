// RED-phase contract tests for the LLM-broker HTTP server (feature 0064,
// §5/§11/§12). These define the OpenAI-compatible /internal/v1/llm/complete
// and /embed contract, the structured typed-error surface, the redaction
// invariants (N6: never a secret/prompt/tool-call arg in an error body),
// and the /livez + /readyz probes (readiness = >=1 healthy provider).
//
// They wire the seams with controllable FAKES (see fakes_test.go) and drive
// the real Server.Handler() routes. Against the current stub (Handler()
// returns 501, Ready() returns ErrNotImplemented) every test FAILS — which
// is the intended RED state. Module agents make them GREEN by implementing
// the handler bodies. Tests MUST NOT be edited to fit the implementation.
package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/broker/budget"
	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/resilience"
	"github.com/vulture/backend/internal/broker/server"
	"github.com/vulture/backend/internal/broker/token"
)

const (
	completePath = "/internal/v1/llm/complete"
	embedPath    = "/internal/v1/llm/embed"
	testBearer   = "Bearer run-token-abc"

	// Sensitive literals we assert never appear in any error response body.
	secretPrompt  = "SUPER-SECRET-PROMPT-audited-source-code"
	secretToolArg = "{\"path\":\"/etc/shadow-SECRET-ARG\"}"
	secretAPIKey  = "sk-live-DO-NOT-LEAK-0123456789"
)

// harness holds the fakes so a test can tweak one before building the server.
type harness struct {
	verifier   *fakeVerifier
	denylist   *fakeDenylist
	revocation *fakeRevocation
	budget     *fakeBudget
	selector   *fakeSelector
	ssrf       *fakeSSRF
	allowlist  *fakeAllowlist
	adapters   map[string]provider.Adapter
	breaker    *passthroughBreaker
	bulkhead   *passthroughBulkhead
	retrier    *passthroughRetrier
	openaiFake *fakeAdapter
	keys       provider.StaticKeys
	// keyedBreakers, when set, overrides the single shared breaker with a
	// per-key map (falling back to h.breaker for unmapped keys).
	keyedBreakers map[string]resilience.CircuitBreaker
}

// breakers builds the BreakerPool the server is wired with.
func (h *harness) breakers() resilience.BreakerPool {
	if h.keyedBreakers != nil {
		return &keyedBreakerPool{m: h.keyedBreakers, def: h.breaker}
	}
	return singleBreakerPool{h.breaker}
}

// newHealthyHarness returns a fully-healthy wiring: a valid token, budget
// that reserves, allowlisted openai provider, SSRF that pins, a passthrough
// resilience stack, and an adapter that returns a well-formed usage.
func newHealthyHarness() *harness {
	oa := &fakeAdapter{
		name: "openai",
		resp: &provider.CompletionResponse{
			Model:        "gpt-4o",
			Provider:     "openai",
			Content:      "hello from the model",
			FinishReason: "stop",
			Usage:        provider.Usage{InputTokens: 120, OutputTokens: 42, CostUSD: 0.0031, Estimated: false},
			RequestID:    "req-1",
		},
	}
	return &harness{
		verifier: &fakeVerifier{claims: &token.Claims{
			Subject:   "run-1",
			TenantID:  "local",
			Scope:     []string{"scan:gpt-4o"},
			BudgetRef: "budget-local",
			Region:    "us",
			JTI:       "jti-1",
			KID:       "kid-1",
			ExpiresAt: 1 << 40, // far future
		}},
		denylist:   &fakeDenylist{denied: map[string]bool{}},
		revocation: &fakeRevocation{revoked: map[string]bool{}},
		budget:     &fakeBudget{remainingUSD: 100},
		selector:   &fakeSelector{sel: &egress.ModelSelection{Model: "gpt-4o", Fallbacks: []string{"gpt-4o-mini"}}},
		ssrf:       &fakeSSRF{},
		allowlist:  &fakeAllowlist{all: true},
		adapters:   map[string]provider.Adapter{"openai": oa},
		breaker:    &passthroughBreaker{},
		bulkhead:   &passthroughBulkhead{},
		retrier:    &passthroughRetrier{},
		openaiFake: oa,
	}
}

func (h *harness) server() *server.Server {
	return server.New(h.deps())
}

// deps builds the Dependencies wiring so tests can tweak fields (e.g.
// DBHealth) before constructing the server.
func (h *harness) deps() server.Dependencies {
	return server.Dependencies{
		Verifier:   h.verifier,
		Denylist:   h.denylist,
		Revocation: h.revocation,
		Budget:     h.budget,
		Selector:   h.selector,
		SSRF:       h.ssrf,
		Allowlist:  h.allowlist,
		Adapters:   h.adapters,
		Keys:       h.keys,
		Breakers:   h.breakers(),
		Bulkheads:  singleBulkheadPool{h.bulkhead},
		Retrier:    h.retrier,
	}
}

// completeBody is a minimal OpenAI-shaped completion request body.
func completeBody() map[string]any {
	return map[string]any{
		"run_id":      "run-1",
		"tenant_id":   "local",
		"task_type":   "scan",
		"model_hint":  "gpt-4o",
		"request_id":  "req-1",
		"max_tokens":  256,
		"temperature": 0.0,
		"messages": []map[string]any{
			{"role": "user", "content": secretPrompt},
		},
	}
}

func doPost(t *testing.T, srv *server.Server, path, bearer string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatalf("encode body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	return rr
}

// errorEnvelope is the structured typed-error contract (§5): a machine code
// plus a retriable flag, never carrying a secret/prompt/tool-arg.
type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retriable bool   `json:"retriable"`
	} `json:"error"`
}

func decodeErr(t *testing.T, rr *httptest.ResponseRecorder) errorEnvelope {
	t.Helper()
	var e errorEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error envelope from %q: %v", rr.Body.String(), err)
	}
	return e
}

// assertNoSecretLeak fails if any secret-class literal appears in the body.
func assertNoSecretLeak(t *testing.T, body string) {
	t.Helper()
	for _, s := range []string{secretPrompt, secretToolArg, secretAPIKey} {
		if strings.Contains(body, s) {
			t.Fatalf("N6 violation: secret-class content leaked in response body: %q contains %q", body, s)
		}
	}
}

// --- happy path ---

func TestHandleComplete_HappyPath_OpenAIShapedResponse(t *testing.T) {
	h := newHealthyHarness()
	srv := h.server()

	rr := doPost(t, srv, completePath, testBearer, completeBody())

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}

	var resp provider.CompletionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%q", err, rr.Body.String())
	}
	if resp.Content != "hello from the model" {
		t.Errorf("content = %q, want %q", resp.Content, "hello from the model")
	}
	if resp.Model != "gpt-4o" {
		t.Errorf("model = %q, want gpt-4o", resp.Model)
	}
	if resp.Provider != "openai" {
		t.Errorf("provider = %q, want openai", resp.Provider)
	}
	if resp.FinishReason != "stop" {
		t.Errorf("finish_reason = %q, want stop", resp.FinishReason)
	}
	// usage{input,output,cost,estimated} must be populated from the adapter.
	if resp.Usage.InputTokens != 120 || resp.Usage.OutputTokens != 42 {
		t.Errorf("usage tokens = %+v, want in=120 out=42", resp.Usage)
	}
	if resp.Usage.CostUSD != 0.0031 {
		t.Errorf("usage cost = %v, want 0.0031", resp.Usage.CostUSD)
	}
	if resp.Usage.Estimated {
		t.Errorf("usage.estimated = true, want false on clean completion")
	}
	if resp.RequestID != "req-1" {
		t.Errorf("request_id = %q, want req-1 (echoed)", resp.RequestID)
	}
}

func TestHandleComplete_HappyPath_PipelineOrder(t *testing.T) {
	h := newHealthyHarness()
	srv := h.server()

	rr := doPost(t, srv, completePath, testBearer, completeBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}

	// token verified
	if h.verifier.calls == 0 {
		t.Error("expected the token to be verified")
	}
	// budget reserved BEFORE the provider call, then reconciled AFTER.
	reserves := h.budget.reserveRequests()
	if len(reserves) != 1 {
		t.Fatalf("expected exactly 1 budget reservation, got %d", len(reserves))
	}
	if reserves[0].RunID != "run-1" || reserves[0].RequestID != "req-1" {
		t.Errorf("reserve keyed wrong: %+v", reserves[0])
	}
	// egress SSRF-checked the resolved base_url.
	if len(h.ssrf.baseURLs) == 0 {
		t.Error("expected the resolved base_url to be SSRF-validated before egress")
	}
	// provider actually called.
	if h.openaiFake.completeReq == nil {
		t.Fatal("expected the provider adapter to be called")
	}
	// budget reconciled with the ACTUAL usage returned by the provider.
	entries := h.budget.reconciledEntries()
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 reconcile, got %d", len(entries))
	}
	if entries[0].InputTokens != 120 || entries[0].OutputTokens != 42 {
		t.Errorf("reconcile tokens = in=%d out=%d, want in=120 out=42", entries[0].InputTokens, entries[0].OutputTokens)
	}
	if entries[0].CostUSD != 0.0031 {
		t.Errorf("reconcile cost = %v, want 0.0031", entries[0].CostUSD)
	}
}

// TestHandleComplete_TenantAndRunFromClaims_NotBody proves the N8 fix: the
// VERIFIED token's tenant_id/run_id are authoritative. A body claiming another
// tenant/run must not redirect budget spend or ledger rows to it.
func TestHandleComplete_TenantAndRunFromClaims_NotBody(t *testing.T) {
	h := newHealthyHarness() // claims: tenant "local", sub "run-1"
	body := completeBody()
	body["tenant_id"] = "victim" // attacker-controlled body values
	body["run_id"] = "victim-run"
	rr := doPost(t, h.server(), "/internal/v1/llm/complete", "Bearer t", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	reqs := h.budget.reserveRequests()
	if len(reqs) != 1 {
		t.Fatalf("want 1 reserve, got %d", len(reqs))
	}
	if reqs[0].TenantID != "local" {
		t.Fatalf("N8: reserve used body tenant %q; must use claims tenant \"local\"", reqs[0].TenantID)
	}
	if reqs[0].RunID != "run-1" {
		t.Fatalf("N8: reserve used body run_id %q; must use claims sub \"run-1\"", reqs[0].RunID)
	}
	if reqs[0].EstimatedUSD <= 0 {
		t.Fatalf("budget reserved $0 — the CAS cap is not enforced pre-flight")
	}
}

// H1 — the token's scope must authorize the request's task_type:model; a
// request outside the granted scope is rejected.
func TestHandleComplete_ScopeNotGranted_Unauthorized(t *testing.T) {
	h := newHealthyHarness() // scope: ["scan:gpt-4o"]
	body := completeBody()
	body["task_type"] = "prove" // required "prove:gpt-4o" is not in the token scope
	rr := doPost(t, h.server(), completePath, testBearer, body)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("scope not granted: status=%d, want 401; body=%q", rr.Code, rr.Body.String())
	}
}

func TestHandleComplete_UsesDefaultModelSelectionPrecedence(t *testing.T) {
	h := newHealthyHarness()
	// selector picks a model the hint didn't name; handler must honor selection.
	h.selector.sel = &egress.ModelSelection{Model: "gpt-4o-mini"}
	// a valid run for gpt-4o-mini must be scoped for it (H1).
	h.verifier.claims.Scope = []string{"scan:gpt-4o", "scan:gpt-4o-mini"}
	h.openaiFake.resp.Model = "gpt-4o-mini"
	srv := h.server()

	rr := doPost(t, srv, completePath, testBearer, completeBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	if h.openaiFake.completeReq == nil {
		t.Fatal("provider not called")
	}
	if h.openaiFake.completeReq.Model != "gpt-4o-mini" {
		t.Errorf("provider called with model %q, want the selector's gpt-4o-mini", h.openaiFake.completeReq.Model)
	}
}

// --- auth / token errors ---

func TestHandleComplete_MissingBearer_Unauthorized(t *testing.T) {
	h := newHealthyHarness()
	srv := h.server()

	rr := doPost(t, srv, completePath, "", completeBody())
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%q", rr.Code, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "unauthorized" {
		t.Errorf("code = %q, want unauthorized", got)
	}
	// must not reach the provider.
	if h.openaiFake.completeReq != nil {
		t.Error("provider must not be called without a valid token")
	}
}

func TestHandleComplete_TokenErrorsMapToTypedCodes(t *testing.T) {
	tests := []struct {
		name     string
		verErr   error
		wantCode string
		wantHTTP int
	}{
		{"unauthorized", token.ErrUnauthorized, "unauthorized", http.StatusUnauthorized},
		{"expired", token.ErrTokenExpired, "token_expired", http.StatusUnauthorized},
		{"revoked", token.ErrTokenRevoked, "token_revoked", http.StatusUnauthorized},
		{"kid_denied", token.ErrKidDenied, "unauthorized", http.StatusUnauthorized},
		{"revocation_unavailable", token.ErrRevocationUnavailable, "revocation_unavailable", http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHealthyHarness()
			h.verifier.claims = nil
			h.verifier.err = tc.verErr
			srv := h.server()

			rr := doPost(t, srv, completePath, testBearer, completeBody())
			if rr.Code != tc.wantHTTP {
				t.Fatalf("status = %d, want %d; body=%q", rr.Code, tc.wantHTTP, rr.Body.String())
			}
			if got := decodeErr(t, rr).Error.Code; got != tc.wantCode {
				t.Errorf("code = %q, want %q", got, tc.wantCode)
			}
			if h.openaiFake.completeReq != nil {
				t.Error("provider must not be called when the token fails verification")
			}
		})
	}
}

func TestHandleComplete_RevokedJTI_TurnBoundaryCheck(t *testing.T) {
	// Token verifies, but the jti is revoked (M3: checked at turn boundary).
	h := newHealthyHarness()
	h.revocation.revoked = map[string]bool{"jti-1": true}
	srv := h.server()

	rr := doPost(t, srv, completePath, testBearer, completeBody())
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%q", rr.Code, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "token_revoked" {
		t.Errorf("code = %q, want token_revoked", got)
	}
	if h.openaiFake.completeReq != nil {
		t.Error("provider must not be called for a revoked run")
	}
}

func TestHandleComplete_DeniedKID_Rejected(t *testing.T) {
	// Emergency mint-key kill: kid on the denylist rejects even a valid sig.
	h := newHealthyHarness()
	h.denylist.denied = map[string]bool{"kid-1": true}
	srv := h.server()

	rr := doPost(t, srv, completePath, testBearer, completeBody())
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%q", rr.Code, rr.Body.String())
	}
	if h.openaiFake.completeReq != nil {
		t.Error("provider must not be called when kid is denied")
	}
}

func TestHandleComplete_RevocationStoreOutage_FailsClosed(t *testing.T) {
	// Revocation store unreachable with no cached answer → fail CLOSED for
	// that call (revocation_unavailable), never let the call through.
	h := newHealthyHarness()
	h.revocation.err = token.ErrRevocationUnavailable
	srv := h.server()

	rr := doPost(t, srv, completePath, testBearer, completeBody())
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%q", rr.Code, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "revocation_unavailable" {
		t.Errorf("code = %q, want revocation_unavailable", got)
	}
	if h.openaiFake.completeReq != nil {
		t.Error("provider must not be called when revocation cannot be resolved (fail-closed)")
	}
}

// --- budget ---

func TestHandleComplete_BudgetExceeded(t *testing.T) {
	h := newHealthyHarness()
	h.budget.reserveErr = budget.ErrBudgetExceeded
	srv := h.server()

	rr := doPost(t, srv, completePath, testBearer, completeBody())
	if rr.Code != http.StatusPaymentRequired && rr.Code != http.StatusTooManyRequests && rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want a budget-exceeded status (402/403/429); body=%q", rr.Code, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "budget_exceeded" {
		t.Errorf("code = %q, want budget_exceeded", got)
	}
	// no reservation ⇒ no provider call ⇒ no reconcile.
	if h.openaiFake.completeReq != nil {
		t.Error("provider must not be called when budget is exceeded")
	}
	if len(h.budget.reconciledEntries()) != 0 {
		t.Error("budget must not be reconciled when reservation failed")
	}
}

// --- egress safety ---

func TestHandleComplete_ProviderNotAllowed(t *testing.T) {
	h := newHealthyHarness()
	h.allowlist = &fakeAllowlist{all: false, allow: map[string]bool{}} // deny all
	srv := h.server()

	rr := doPost(t, srv, completePath, testBearer, completeBody())
	if rr.Code == http.StatusOK {
		t.Fatalf("expected non-200 for a non-allowlisted provider; body=%q", rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "provider_unavailable" && got != "invalid_request" {
		t.Errorf("code = %q, want provider_unavailable or invalid_request", got)
	}
	if h.openaiFake.completeReq != nil {
		t.Error("provider must not be called when not allowlisted")
	}
}

func TestHandleComplete_SSRFBlocked(t *testing.T) {
	h := newHealthyHarness()
	h.ssrf.err = egress.ErrSSRFBlocked
	srv := h.server()

	rr := doPost(t, srv, completePath, testBearer, completeBody())
	if rr.Code == http.StatusOK {
		t.Fatalf("expected non-200 when SSRF validation blocks the base_url; body=%q", rr.Body.String())
	}
	code := decodeErr(t, rr).Error.Code
	if code != "provider_unavailable" && code != "invalid_request" {
		t.Errorf("code = %q, want provider_unavailable or invalid_request", code)
	}
	if h.openaiFake.completeReq != nil {
		t.Error("provider must not be called when SSRF is blocked")
	}
}

// --- provider / resilience errors ---

func TestHandleComplete_ProviderErrorsMapToTypedCodes(t *testing.T) {
	tests := []struct {
		name     string
		provErr  error
		wantCode string
		wantHTTP int
	}{
		{"rate_limited", provider.ErrRateLimited, "rate_limited", http.StatusTooManyRequests},
		{"unavailable", provider.ErrProviderUnavailable, "provider_unavailable", http.StatusBadGateway},
		{"usage_missing", provider.ErrUsageMissing, "provider_unavailable", http.StatusBadGateway},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHealthyHarness()
			h.openaiFake.resp = nil
			h.openaiFake.err = tc.provErr
			srv := h.server()

			rr := doPost(t, srv, completePath, testBearer, completeBody())
			if rr.Code != tc.wantHTTP {
				t.Fatalf("status = %d, want %d; body=%q", rr.Code, tc.wantHTTP, rr.Body.String())
			}
			if got := decodeErr(t, rr).Error.Code; got != tc.wantCode {
				t.Errorf("code = %q, want %q", got, tc.wantCode)
			}
		})
	}
}

func TestHandleComplete_BulkheadFull_RateLimited(t *testing.T) {
	h := newHealthyHarness()
	h.bulkhead.forceErr = resilience.ErrBulkheadFull
	srv := h.server()

	rr := doPost(t, srv, completePath, testBearer, completeBody())
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body=%q", rr.Code, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "rate_limited" {
		t.Errorf("code = %q, want rate_limited", got)
	}
}

func TestHandleComplete_AllProvidersDown(t *testing.T) {
	// Circuit open on the only provider with no viable fallback → all down.
	h := newHealthyHarness()
	h.breaker.forceErr = resilience.ErrCircuitOpen
	h.selector.sel = &egress.ModelSelection{Model: "gpt-4o"} // no fallbacks
	srv := h.server()

	rr := doPost(t, srv, completePath, testBearer, completeBody())
	if rr.Code != http.StatusServiceUnavailable && rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 503/502; body=%q", rr.Code, rr.Body.String())
	}
	code := decodeErr(t, rr).Error.Code
	if code != "all_providers_down" && code != "provider_unavailable" {
		t.Errorf("code = %q, want all_providers_down or provider_unavailable", code)
	}
}

// --- request validation ---

func TestHandleComplete_InvalidJSON(t *testing.T) {
	h := newHealthyHarness()
	srv := h.server()

	req := httptest.NewRequest(http.MethodPost, completePath, strings.NewReader("{not-json"))
	req.Header.Set("Authorization", testBearer)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", rr.Code, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "invalid_request" {
		t.Errorf("code = %q, want invalid_request", got)
	}
}

func TestHandleComplete_WrongMethod(t *testing.T) {
	h := newHealthyHarness()
	srv := h.server()

	req := httptest.NewRequest(http.MethodGet, completePath, nil)
	req.Header.Set("Authorization", testBearer)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405; body=%q", rr.Code, rr.Body.String())
	}
}

// --- N6: never leak secret-class content in an error body ---

func TestHandleComplete_ErrorBodiesNeverLeakSecrets(t *testing.T) {
	// Drive several failure modes and assert the prompt, tool-arg, and API
	// key never appear in any error body (N6). The request carries a
	// secret prompt + tool arg; the credentials carry a secret key.
	body := completeBody()
	body["tools"] = []map[string]any{
		{"type": "function", "name": "read_file", "parameters": map[string]any{"raw": secretToolArg}},
	}
	body["messages"] = []map[string]any{
		{"role": "user", "content": secretPrompt},
		{"role": "assistant", "tool_calls": []map[string]any{
			{"id": "tc1", "type": "function", "name": "read_file", "arguments": secretToolArg},
		}},
	}

	failures := []struct {
		name  string
		mutdo func(*harness)
	}{
		{"token_error", func(h *harness) { h.verifier.claims = nil; h.verifier.err = token.ErrUnauthorized }},
		{"budget_exceeded", func(h *harness) { h.budget.reserveErr = budget.ErrBudgetExceeded }},
		{"ssrf_blocked", func(h *harness) { h.ssrf.err = egress.ErrSSRFBlocked }},
		{"provider_error", func(h *harness) {
			h.openaiFake.resp = nil
			h.openaiFake.err = provider.ErrProviderUnavailable
			h.ssrf.target = &egress.PinnedTarget{URL: "https://api.openai.com", IP: "203.0.113.10", Provider: "openai"}
		}},
	}
	for _, f := range failures {
		t.Run(f.name, func(t *testing.T) {
			h := newHealthyHarness()
			// Inject a secret API key on the adapter's seen credentials path.
			h.openaiFake.seenCreds = provider.Credentials{Provider: "openai", APIKey: secretAPIKey}
			f.mutdo(h)
			srv := h.server()

			rr := doPost(t, srv, completePath, testBearer, body)
			if rr.Code == http.StatusOK {
				t.Fatalf("expected a failure status for %s", f.name)
			}
			assertNoSecretLeak(t, rr.Body.String())
		})
	}
}

// --- embeddings ---

func TestHandleEmbed_HappyPath(t *testing.T) {
	h := newHealthyHarness()
	h.openaiFake.embedResp = &provider.EmbeddingResponse{
		Model:      "text-embedding-3-small",
		Provider:   "openai",
		Embeddings: [][]float32{{0.1, 0.2, 0.3}},
		Usage:      provider.Usage{InputTokens: 8, CostUSD: 0.00001},
		RequestID:  "emb-1",
	}
	srv := h.server()

	body := map[string]any{
		"run_id":     "run-1",
		"tenant_id":  "local",
		"model":      "text-embedding-3-small",
		"request_id": "emb-1",
		"inputs":     []string{"chunk a", "chunk b"},
	}
	rr := doPost(t, srv, embedPath, testBearer, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	var resp provider.EmbeddingResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%q", err, rr.Body.String())
	}
	if len(resp.Embeddings) != 1 || len(resp.Embeddings[0]) != 3 {
		t.Errorf("embeddings shape = %v, want 1x3", resp.Embeddings)
	}
	if resp.Usage.InputTokens != 8 {
		t.Errorf("usage.input_tokens = %d, want 8", resp.Usage.InputTokens)
	}
}

func TestHandleEmbed_RequiresToken(t *testing.T) {
	h := newHealthyHarness()
	srv := h.server()
	body := map[string]any{"run_id": "run-1", "tenant_id": "local", "inputs": []string{"x"}}
	rr := doPost(t, srv, embedPath, "", body)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%q", rr.Code, rr.Body.String())
	}
}

// --- health / readiness probes (§12) ---

func TestLivez_AlwaysOK(t *testing.T) {
	h := newHealthyHarness()
	srv := h.server()

	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/livez status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
}

func TestReadyz_HealthyProvider_Ready(t *testing.T) {
	h := newHealthyHarness()
	srv := h.server()

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/readyz status = %d, want 200 with >=1 healthy provider; body=%q", rr.Code, rr.Body.String())
	}
}

func TestReadyz_NoProviders_NotReady(t *testing.T) {
	// readiness = >=1 healthy provider only; empty adapter set ⇒ not ready.
	h := newHealthyHarness()
	h.adapters = map[string]provider.Adapter{}
	srv := h.server()

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want 503 with no providers; body=%q", rr.Code, rr.Body.String())
	}
}

func TestReady_Probe_HealthyProvider(t *testing.T) {
	h := newHealthyHarness()
	srv := h.server()
	ok, err := srv.Ready(context.Background())
	if err != nil {
		t.Fatalf("Ready err = %v, want nil when a healthy provider exists", err)
	}
	if !ok {
		t.Fatal("Ready = false, want true with >=1 healthy provider")
	}
}

func TestReady_Probe_NoProviders_NotReady(t *testing.T) {
	h := newHealthyHarness()
	h.adapters = map[string]provider.Adapter{}
	srv := h.server()
	ok, _ := srv.Ready(context.Background())
	if ok {
		t.Fatal("Ready = true with zero providers, want false")
	}
}

// Ensure the readiness probe seam is still satisfied by the concrete Server.
var _ server.ReadinessProbe = (*server.Server)(nil)
