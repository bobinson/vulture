package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/vulture/backend/internal/broker/budget"
	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/token"
)

// defaultProvider is the OpenAI-compatible broker default (§5). Adapters are
// keyed by provider name; the broker resolves this one unless overridden.
const defaultProvider = "openai"

// defaultOpenAIBaseURL is the canonical first-party endpoint validated + pinned
// by the SSRF guard when no tenant BYO base_url is configured. Passing a REAL
// URL (never "") ensures the SSRF validator actually runs in the request path.
const defaultOpenAIBaseURL = "https://api.openai.com/v1"

// reserveTTL bounds a budget lease; it must be >= the call timeout (§8).
const reserveTTL = 2 * time.Minute

// HandleComplete serves POST /internal/v1/llm/complete (§5). It runs the
// verify → reserve → select → egress-check → call → reconcile pipeline and
// renders an OpenAI-shaped response or a typed error. Delegates so each
// helper stays under cyclomatic complexity 5.
func (s *Server) HandleComplete(w http.ResponseWriter, r *http.Request) {
	claims, apiErr := s.guardRequest(r)
	if apiErr != nil {
		writeErr(w, apiErr)
		return
	}
	var req completeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, errInvalidRequest)
		return
	}
	resp, apiErr := s.runComplete(r.Context(), claims, &req)
	if apiErr != nil {
		writeErr(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// runComplete executes the post-auth completion pipeline (§5/§7/§8/§9):
// prepare (select → egress-check → reserve) then call → reconcile.
func (s *Server) runComplete(ctx context.Context, claims *token.Claims, req *completeRequest) (*provider.CompletionResponse, *apiError) {
	// N8: identity is authoritative from the VERIFIED token, never the client
	// body — a valid token for tenant A must not be able to act as tenant B or
	// forge another run's budget/ledger/audit rows.
	req.TenantID = claims.TenantID
	req.RunID = claims.Subject
	sel, target, apiErr := s.prepare(ctx, claims, req)
	if apiErr != nil {
		return nil, apiErr
	}
	resp, apiErr := s.callProvider(ctx, target, buildCompletionRequest(req, sel.Model))
	if apiErr != nil {
		return nil, apiErr
	}
	s.reconcile(ctx, req, resp)
	resp.RequestID = req.RequestID
	return resp, nil
}

// prepare resolves the model, gates + pins egress, then reserves budget — in
// that order so no spend is reserved for a blocked egress target (§7/§8/§11).
func (s *Server) prepare(ctx context.Context, claims *token.Claims, req *completeRequest) (*egress.ModelSelection, *egress.PinnedTarget, *apiError) {
	sel, apiErr := s.selectModel(req)
	if apiErr != nil {
		return nil, nil, apiErr
	}
	// H1: enforce the token's scope against the resolved task_type:model BEFORE
	// any egress gating or budget reservation (fail fast, no spend reserved for
	// an unauthorized scope).
	if apiErr := checkScope(claims, req.TaskType, sel.Model); apiErr != nil {
		return nil, nil, apiErr
	}
	target, apiErr := s.egressCheck(sel)
	if apiErr != nil {
		return nil, nil, apiErr
	}
	if apiErr := s.reserve(ctx, req, sel.Model); apiErr != nil {
		return nil, nil, apiErr
	}
	return sel, target, nil
}

// checkScope rejects a request whose task_type:model is not in the verified
// token's scope claim (H1). The scope claim is authoritative, not decorative.
func checkScope(c *token.Claims, taskType, model string) *apiError {
	if !c.AllowsScope(taskType + ":" + model) {
		return errUnauthorized
	}
	return nil
}

// selectModel resolves the model + fallback chain with residency (§7).
func (s *Server) selectModel(req *completeRequest) (*egress.ModelSelection, *apiError) {
	sel, err := s.deps.Selector.Select(req.ModelHint, egress.PolicyContext{TaskType: req.TaskType})
	if err != nil {
		return nil, errInvalidRequest
	}
	return sel, nil
}

// egressCheck gates the provider on the allowlist then SSRF-validates and
// pins the resolved base URL (§7/§11) BEFORE any spend is reserved.
func (s *Server) egressCheck(_ *egress.ModelSelection) (*egress.PinnedTarget, *apiError) {
	prov := defaultProvider
	if !s.deps.Allowlist.Allowed(prov) {
		return nil, errProviderNotAllowlist
	}
	target, err := s.deps.SSRF.Validate(prov, defaultOpenAIBaseURL)
	if err != nil {
		return nil, mapEgressErr(err)
	}
	return target, nil
}

// adapterFor resolves the pinned target to its provider adapter and builds
// the (SSRF-pinned) credentials the transport dials (§9/§11).
func (s *Server) adapterFor(target *egress.PinnedTarget) (provider.Adapter, provider.Credentials, *apiError) {
	adapter, ok := s.deps.Adapters[target.Provider]
	if !ok {
		return nil, provider.Credentials{}, errProviderNotAllowlist
	}
	creds := provider.Credentials{Provider: target.Provider, BaseURL: target.URL}
	return adapter, creds, nil
}

// reserve CAS-reserves budget for one call keyed by (run_id,request_id) (§8).
func (s *Server) reserve(ctx context.Context, req *completeRequest, model string) *apiError {
	_, err := s.deps.Budget.Reserve(ctx, budget.ReserveRequest{
		RunID:         req.RunID,
		RequestID:     req.RequestID,
		TenantID:      req.TenantID,
		EstimatedUSD:  provider.EstimateUSD(model, req.MaxTokens),
		ModelSnapshot: model,
		LeaseTTL:      reserveTTL,
	})
	if err != nil {
		return mapBudgetErr(err)
	}
	return nil
}

// callProvider runs the adapter under the resilience stack (bulkhead →
// breaker → retrier) and enforces the usage-sanity floor (§9/§11).
func (s *Server) callProvider(ctx context.Context, target *egress.PinnedTarget, req provider.CompletionRequest) (*provider.CompletionResponse, *apiError) {
	// §9/§16: bound the provider call so a hung/slow provider cannot hold the
	// goroutine, bulkhead slot, and budget lease indefinitely.
	if s.deps.CallTimeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(s.deps.CallTimeoutSec)*time.Second)
		defer cancel()
	}
	adapter, creds, apiErr := s.adapterFor(target)
	if apiErr != nil {
		return nil, apiErr
	}
	var resp *provider.CompletionResponse
	err := s.guard(ctx, func(c context.Context) error {
		r, e := adapter.Complete(c, creds, req)
		resp = r
		return e
	})
	if err != nil {
		return nil, mapProviderErr(err)
	}
	if !usageOK(resp) {
		return nil, errProviderUnavailable
	}
	return resp, nil
}

// reconcile charges the ACTUAL usage returned by the provider and releases
// the lease (§8/M1). Reconcile failure is not surfaced to the caller — the
// completion already succeeded; the sweeper reclaims a stale lease (§8).
func (s *Server) reconcile(ctx context.Context, req *completeRequest, resp *provider.CompletionResponse) {
	_ = s.deps.Budget.Reconcile(ctx, budget.LedgerEntry{
		RunID:        req.RunID,
		RequestID:    req.RequestID,
		TenantID:     req.TenantID,
		Model:        resp.Model,
		Provider:     resp.Provider,
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
		CostUSD:      resp.Usage.CostUSD,
		Estimated:    resp.Usage.Estimated,
	})
}

// guard composes the resilience wrappers around fn (§9): bulkhead sheds
// fast, the breaker fails over on open, the retrier applies the budget.
func (s *Server) guard(ctx context.Context, fn func(context.Context) error) error {
	return s.deps.Bulkhead.Execute(ctx, func(c1 context.Context) error {
		return s.deps.Breakers.Execute(c1, func(c2 context.Context) error {
			return s.deps.Retrier.Execute(c2, fn)
		})
	})
}

// usageOK enforces the usage-sanity floor: a clean completion must be
// present and report a non-zero token count, never $0/zero usage (§11).
func usageOK(resp *provider.CompletionResponse) bool {
	return resp != nil && (resp.Usage.InputTokens > 0 || resp.Usage.OutputTokens > 0)
}

// buildCompletionRequest normalizes the HTTP body into the adapter request,
// pinning the selector-chosen model (selection precedence, §7).
func buildCompletionRequest(req *completeRequest, model string) provider.CompletionRequest {
	return provider.CompletionRequest{
		RunID:          req.RunID,
		TenantID:       req.TenantID,
		TaskType:       req.TaskType,
		Model:          model,
		Messages:       req.Messages,
		Tools:          req.Tools,
		ToolChoice:     req.ToolChoice,
		MaxTokens:      req.MaxTokens,
		Temperature:    req.Temperature,
		Stream:         false,
		ResponseFormat: req.ResponseFormat,
		RequestID:      req.RequestID,
	}
}
