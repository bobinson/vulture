package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/vulture/backend/internal/broker/budget"
	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/resilience"
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
	req, apiErr := decodeChatRequest(w, r)
	if apiErr != nil {
		writeErr(w, apiErr)
		return
	}
	resp, apiErr := s.runComplete(r.Context(), claims, req)
	if apiErr != nil {
		writeErr(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, renderChatCompletion(resp))
}

// runComplete executes the post-auth completion pipeline (§5/§7/§8/§9):
// prepare (select → egress-check → reserve) then call → reconcile.
func (s *Server) runComplete(ctx context.Context, claims *token.Claims, req *completeRequest) (*provider.CompletionResponse, *apiError) {
	// N8: identity is authoritative from the VERIFIED token, never the client
	// body — a valid token for tenant A must not be able to act as tenant B or
	// forge another run's budget/ledger/audit rows.
	req.TenantID = claims.TenantID
	req.RunID = claims.Subject
	cands, target, apiErr := s.prepare(ctx, claims, req)
	if apiErr != nil {
		return nil, apiErr
	}
	resp, apiErr := s.tryCandidates(ctx, claims, req, cands, target)
	if apiErr != nil {
		return nil, apiErr
	}
	// The provider call happened and incurred cost — meter it honestly before
	// any post-hoc rejection.
	s.reconcile(ctx, req, resp)
	// §9/H2: reject a tool-call flood (a prompt-injected model must not be able
	// to overflow the parser/ledger/stream). Enforced AFTER metering so the
	// real spend is still charged.
	if !toolOutputWithinBounds(resp) {
		return nil, errToolOutputTooLarge
	}
	resp.RequestID = req.RequestID
	return resp, nil
}

// per-turn tool-call bounds (§9/H2). Constants for P0; can become config if a
// deployment needs to tune them.
const (
	maxToolCallsPerTurn    = 64
	maxToolArgBytesPerTurn = 256 << 10 // 256 KiB aggregate argument bytes
)

// toolOutputWithinBounds reports whether a completion's relayed tool calls are
// within the per-turn count + aggregate-argument-byte caps.
func toolOutputWithinBounds(resp *provider.CompletionResponse) bool {
	if len(resp.ToolCalls) > maxToolCallsPerTurn {
		return false
	}
	total := 0
	for _, tc := range resp.ToolCalls {
		total += len(tc.Arguments)
		if total > maxToolArgBytesPerTurn {
			return false
		}
	}
	return true
}

// tryCandidates walks the resolved candidate chain (§7/§9): the primary
// first, then each fallback re-gated through scope + allowlist + SSRF (a
// gate-blocked candidate is skipped, never called). Failover happens only on
// provider-unavailable / circuit-open; other errors surface immediately.
// Exhausting ≥2 tried candidates is all_providers_down; a chain whose viable
// set was a single candidate surfaces that candidate's own error.
func (s *Server) tryCandidates(ctx context.Context, claims *token.Claims, req *completeRequest, cands []egress.Candidate, target *egress.PinnedTarget) (*provider.CompletionResponse, *apiError) {
	called := 0
	var lastErr error
	for i, c := range cands {
		t := target
		if i > 0 {
			var apiErr *apiError
			if t, apiErr = s.gateFallback(claims, req, c); apiErr != nil {
				continue
			}
		}
		called++
		resp, err := s.callOnce(ctx, t, buildCompletionRequest(req, c.Model))
		if err == nil {
			return resp, nil
		}
		if !isFailover(err) {
			return nil, mapProviderErr(err)
		}
		lastErr = err
	}
	if called >= 2 {
		return nil, errAllProvidersDown
	}
	return nil, mapProviderErr(lastErr)
}

// gateFallback re-applies the scope + egress gates to a fallback candidate
// (§7/§11) — failover never bypasses authorization or SSRF.
func (s *Server) gateFallback(claims *token.Claims, req *completeRequest, c egress.Candidate) (*egress.PinnedTarget, *apiError) {
	if apiErr := checkScope(claims, req.TaskType, c.Model); apiErr != nil {
		return nil, apiErr
	}
	return s.egressCheck(c)
}

// isFailover reports whether err should advance the candidate chain (§9):
// only provider-unavailable and circuit-open fail over; rate limits, budget
// and validation errors surface immediately.
func isFailover(err error) bool {
	return errors.Is(err, provider.ErrProviderUnavailable) ||
		errors.Is(err, resilience.ErrCircuitOpen)
}

// prepare resolves the model, gates + pins egress, then reserves budget — in
// that order so no spend is reserved for a blocked egress target (§7/§8/§11).
// It returns the full candidate chain (primary first) and the primary's
// pinned target. The single reservation is keyed to the primary's max-price
// estimate; fallbacks reuse it (reconcile charges the ACTUAL model/usage).
func (s *Server) prepare(ctx context.Context, claims *token.Claims, req *completeRequest) ([]egress.Candidate, *egress.PinnedTarget, *apiError) {
	sel, apiErr := s.selectModel(req)
	if apiErr != nil {
		return nil, nil, apiErr
	}
	cands := sel.Candidates()
	primary := cands[0]
	// H1: enforce the token's scope against the resolved task_type:model BEFORE
	// any egress gating or budget reservation (fail fast, no spend reserved for
	// an unauthorized scope).
	if apiErr := checkScope(claims, req.TaskType, primary.Model); apiErr != nil {
		return nil, nil, apiErr
	}
	target, apiErr := s.egressCheck(primary)
	if apiErr != nil {
		return nil, nil, apiErr
	}
	if apiErr := s.reserve(ctx, req, primary.Model); apiErr != nil {
		return nil, nil, apiErr
	}
	return cands, target, nil
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

// egressCheck gates ONE candidate's route on the allowlist then
// SSRF-validates and pins its base URL (§7/§11) BEFORE any spend is
// reserved. It is re-applied to EVERY fallback candidate — failover must
// never skip the gate.
func (s *Server) egressCheck(c egress.Candidate) (*egress.PinnedTarget, *apiError) {
	prov := c.Provider
	if prov == "" {
		prov = defaultProvider
	}
	if !s.deps.Allowlist.Allowed(prov) {
		return nil, errProviderNotAllowlist
	}
	base := c.BaseURL
	if base == "" && prov == defaultProvider {
		base = defaultOpenAIBaseURL
	}
	target, err := s.deps.SSRF.Validate(prov, base)
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
	creds := provider.Credentials{
		Provider: target.Provider,
		BaseURL:  target.URL,
		// §11 DNS-rebinding defense: the transport dials the exact IP the
		// SSRF validator resolved and allow-checked, never re-resolving.
		PinnedIP: target.IP,
		// N1: the broker resolves the provider key; agents never hold it.
		APIKey: s.keyFor(target.Provider),
	}
	return adapter, creds, nil
}

// keyFor resolves the broker-held API key for a provider ("" when no
// resolver is wired or the provider has no key — keyless local endpoints).
func (s *Server) keyFor(provider string) string {
	if s.deps.Keys == nil {
		return ""
	}
	return s.deps.Keys.KeyFor(provider)
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

// callOnce runs ONE candidate's adapter call under the resilience stack,
// returning the raw error so the fallback loop can classify failover (§9).
func (s *Server) callOnce(ctx context.Context, target *egress.PinnedTarget, req provider.CompletionRequest) (*provider.CompletionResponse, error) {
	// §9/§16: bound the provider call so a hung/slow provider cannot hold the
	// goroutine, bulkhead slot, and budget lease indefinitely.
	if s.deps.CallTimeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(s.deps.CallTimeoutSec)*time.Second)
		defer cancel()
	}
	adapter, creds, apiErr := s.adapterFor(target)
	if apiErr != nil {
		return nil, provider.ErrProviderUnavailable
	}
	var resp *provider.CompletionResponse
	err := s.guard(ctx, target.Provider, target.Provider+":"+req.Model, func(c context.Context) error {
		r, e := adapter.Complete(c, creds, req)
		resp = r
		return e
	})
	if err != nil {
		return nil, err
	}
	if !usageOK(resp) {
		return nil, provider.ErrUsageMissing
	}
	return resp, nil
}

// reconcile charges the ACTUAL usage returned by the provider and releases
// the lease (§8/M1). The completion already succeeded, so a reconcile failure
// is not surfaced to the caller — but it is LOGGED (§26/H3), never silently
// swallowed, since a persistent failure means real spend stops counting.
func (s *Server) reconcile(ctx context.Context, req *completeRequest, resp *provider.CompletionResponse) {
	entry := budget.LedgerEntry{
		RunID:        req.RunID,
		RequestID:    req.RequestID,
		TenantID:     req.TenantID,
		Model:        resp.Model,
		Provider:     resp.Provider,
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
		CostUSD:      resp.Usage.CostUSD,
		Estimated:    resp.Usage.Estimated,
	}
	if err := s.deps.Budget.Reconcile(ctx, entry); err != nil {
		s.logReconcileFailure(req.RunID, req.RequestID, err)
	}
	s.auditLog(ctx, entry, resp.Cached)
}

// auditLog records the §14 P0 metering row for a completion (best-effort).
func (s *Server) auditLog(ctx context.Context, e budget.LedgerEntry, cached bool) {
	if s.deps.AuditLog != nil {
		s.deps.AuditLog.Log(ctx, e, cached)
	}
}

// logReconcileFailure records a reconcile failure (§26/H3). Secret-free: only
// identifiers and the error class, never prompt/completion content (N6).
func (s *Server) logReconcileFailure(runID, requestID string, err error) {
	log.Printf("broker: reconcile failed run=%s request=%s: %v", runID, requestID, err)
}

// guard composes the resilience wrappers around fn (§9): the PER-PROVIDER
// bulkhead sheds fast, the PER-(provider,model) breaker fails over on open,
// the retrier applies the retry budget.
func (s *Server) guard(ctx context.Context, providerKey, breakerKey string, fn func(context.Context) error) error {
	return s.deps.Bulkheads.For(providerKey).Execute(ctx, func(c1 context.Context) error {
		return s.deps.Breakers.For(breakerKey).Execute(c1, func(c2 context.Context) error {
			return s.deps.Retriers.For(providerKey).Execute(c2, fn)
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
		RequestID:      req.RequestID,
	}
}
