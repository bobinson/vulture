package server

import (
	"context"
	"errors"
	"fmt"
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

// fallbackLeaseTTL is the lease bound when the broker's per-call deadline is
// disabled (CallTimeoutSec <= 0: unit tests, or an operator who set it to 0).
// leaseTTL then has no deadline to size the lease from: each HTTP attempt is
// still capped by the adapters' own client timeout (serve.defaultAdapters), but
// the retrier may make several and that cap is not visible here, so the
// historical fixed TTL stands. A call that outlives it is still charged at
// reconcile (the swept-lease fallback); only the cap is unguarded meanwhile.
const fallbackLeaseTTL = 2 * time.Minute

// leaseSlack covers what follows the last provider call before reconcile
// deletes the lease: decoding the answer and the reconcile transaction itself.
const leaseSlack = time.Minute

// releaseTimeout bounds handing a lease back. The release runs after the
// caller may have gone, so it cannot borrow the request's cancellation.
const releaseTimeout = 10 * time.Second

// AdmissionWait is how long a request may queue for a provider slot before the
// broker sheds it as rate_limited: one call timeout. The agents bound each
// request by that timeout or a shorter one, so a request still queued past it
// belongs to a caller that has already given up — the bound only stops a
// stalled queue from holding it forever. Being a bound is also what lets the
// budget lease be sized to outlive the queue (see leaseTTL). 0 (no call timeout
// configured) leaves the wait bounded by the request context alone.
func AdmissionWait(callTimeoutSec int) time.Duration {
	if callTimeoutSec <= 0 {
		return 0
	}
	return time.Duration(callTimeoutSec) * time.Second
}

// leaseTTL sizes a budget lease to outlive its request (§8): every candidate the
// chain may try can queue up to AdmissionWait for a slot and then run up to the
// call timeout. The fixed two-minute lease this replaces expired under a single
// 439 s call, and the sweeper then returned a live reservation to the cap.
func (s *Server) leaseTTL(candidates int) time.Duration {
	perCandidate := AdmissionWait(s.deps.CallTimeoutSec) + s.callTimeout()
	if perCandidate <= 0 {
		return fallbackLeaseTTL
	}
	return time.Duration(candidates)*perCandidate + leaseSlack
}

// callTimeout is the per-call bound (§9/§16, VULTURE_LLM_CALL_TIMEOUT_SEC);
// <= 0 when the guard is disabled.
func (s *Server) callTimeout() time.Duration {
	return time.Duration(s.deps.CallTimeoutSec) * time.Second
}

// statusClientClosedRequest is the "client closed request" status returned when
// the CALLER abandoned the request. net/http has no constant for it; 499 is the
// widely-deployed (nginx) convention and, unlike 502/503, it does not blame the
// upstream provider for a decision the caller made.
const statusClientClosedRequest = 499

// errCallerAborted is the egress sentinel for "the CALLER walked away" — an
// inherited context cancellation, NOT a provider fault. It follows the
// package's existing sentinel vocabulary (provider.ErrProviderUnavailable,
// resilience.ErrCircuitOpen): the loop classifies it with errors.Is, and the
// underlying context cause is wrapped so the server-side log still shows WHICH
// context error fired.
var errCallerAborted = errors.New("broker/server: caller aborted the request")

// errRequestAborted is the client-facing typed error for a caller-abandoned
// request. retriable=false: the broker stopped because the CALLER stopped, so
// an agent must not read it as "the provider was down" and retry — the two
// warrant different behavior. Declared alongside the abort sentinel it maps
// from; the rest of the §5 vocabulary lives in errors.go.
var errRequestAborted = &apiError{code: "request_aborted", message: "request aborted by caller", status: statusClientClosedRequest, retriable: false}

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
	// The caller is already gone: stop here. Reserving budget for an abandoned
	// request leaves a lease nothing will reconcile, and dialing a provider on
	// its behalf spends real money on an answer nobody will read.
	if err := callerAborted(ctx); err != nil {
		log.Printf("broker: request aborted before egress (caller cancelled) run=%s request=%s: %v", req.RunID, req.RequestID, err)
		return nil, errRequestAborted
	}
	cands, target, apiErr := s.prepare(ctx, claims, req)
	if apiErr != nil {
		return nil, apiErr
	}
	resp, apiErr := s.callCandidates(ctx, claims, req, cands, target)
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

// callCandidates runs the candidate chain and, when it fails — for any reason,
// before or after a call reached a provider — hands the request's lease
// straight back. Only a completion that came back is ever reconciled, so a
// failed request's lease would be returned uncharged by the sweeper anyway;
// holding it until then only blocks a capped budget, for the lease's whole TTL.
func (s *Server) callCandidates(ctx context.Context, claims *token.Claims, req *completeRequest, cands []egress.Candidate, target *egress.PinnedTarget) (*provider.CompletionResponse, *apiError) {
	resp, apiErr := s.tryCandidates(ctx, claims, req, cands, target)
	if apiErr != nil {
		s.releaseLease(ctx, req.RunID, req.RequestID)
	}
	return resp, apiErr
}

// releaseLease hands an unreconciled lease back when the budget store can
// (budget.Releaser); otherwise the sweeper reclaims it after its TTL. A failed
// release is logged and left to the sweeper, never surfaced: the request has
// already failed for its own reason.
func (s *Server) releaseLease(ctx context.Context, runID, requestID string) {
	r, ok := s.deps.Budget.(budget.Releaser)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()
	if err := r.Release(ctx, runID, requestID); err != nil {
		log.Printf("broker: lease release failed run=%s request=%s (the sweeper will reclaim it): %v", runID, requestID, err)
	}
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
		s.noteOverflow(err)
		if apiErr := classifyEgressErr(t.Provider, c.Model, err); apiErr != nil {
			return nil, apiErr
		}
		lastErr = err
	}
	if called >= 2 {
		return nil, errAllProvidersDown
	}
	return nil, mapProviderErrWithUpstream(lastErr)
}

// classifyEgressErr logs ONE candidate's failure and returns the typed error to
// surface, or nil when the chain should advance to the next candidate.
//
// A caller cancellation is classified BEFORE the isFailover test: it is neither
// a failover cause nor a provider fault, so it stops the chain (walking the
// fallbacks for a caller who has gone away only burns spend) and surfaces the
// distinct request_aborted code.
//
// §32: the failure cause is logged server-side and is secret-free — the adapter
// carries only the upstream STATUS code / transport cause, never the response
// body or key (N6) — so an operator can see WHY a provider call failed instead
// of only the scrubbed client-facing provider_unavailable.
func classifyEgressErr(prov, model string, err error) *apiError {
	if errors.Is(err, errCallerAborted) {
		// Never "egress failed provider=" here: the provider did nothing wrong,
		// and blaming it sends an operator hunting a phantom outage (and can look
		// like a provider regression in the logs of a healthy deployment).
		log.Printf("broker: egress aborted (caller cancelled) provider=%s model=%s: %v", prov, model, err)
		return errRequestAborted
	}
	log.Printf("broker: egress failed provider=%s model=%s: %v", prov, model, err)
	if !isFailover(err) {
		return mapProviderErrWithUpstream(err)
	}
	return nil
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
	if apiErr := s.reserve(ctx, req, primary.Model, s.leaseTTL(len(cands))); apiErr != nil {
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
	dp, dbu := s.defaultRoute()
	prov := c.Provider
	if prov == "" {
		prov = dp
	}
	if !s.deps.Allowlist.Allowed(prov) {
		return nil, errProviderNotAllowlist
	}
	base := c.BaseURL
	if base == "" && prov == dp {
		base = dbu
	}
	target, err := s.deps.SSRF.Validate(prov, base)
	if err != nil {
		return nil, mapEgressErr(err)
	}
	return target, nil
}

// defaultRoute returns the configured default provider + base URL, falling
// back to first-party OpenAI when unset (§5/§25.2). Lets a self-host
// deployment point the broker at a local OpenAI-compatible server.
func (s *Server) defaultRoute() (provider, baseURL string) {
	provider, baseURL = s.deps.DefaultProvider, s.deps.DefaultBaseURL
	if provider == "" {
		provider = defaultProvider
	}
	if baseURL == "" && provider == defaultProvider {
		baseURL = defaultOpenAIBaseURL
	}
	return provider, baseURL
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

// reserve CAS-reserves budget for one call keyed by (run_id,request_id) (§8),
// under a lease sized to outlive the request (leaseTTL).
func (s *Server) reserve(ctx context.Context, req *completeRequest, model string, ttl time.Duration) *apiError {
	_, err := s.deps.Budget.Reserve(ctx, budget.ReserveRequest{
		RunID:         req.RunID,
		RequestID:     req.RequestID,
		TenantID:      req.TenantID,
		EstimatedUSD:  provider.EstimateUSD(model, req.MaxTokens),
		ModelSnapshot: model,
		LeaseTTL:      ttl,
	})
	if err != nil {
		return mapBudgetErr(err)
	}
	return nil
}

// callOnce runs ONE candidate's adapter call under the resilience stack,
// returning the raw error so the fallback loop can classify failover (§9).
// ctx is the CALLER's context: the broker's own per-call deadline is derived
// inside guard, after admission, and keeping the two apart is what makes their
// cancellations tellable apart (see attributeCtxErr).
func (s *Server) callOnce(ctx context.Context, target *egress.PinnedTarget, req provider.CompletionRequest) (*provider.CompletionResponse, error) {
	// The caller went away (possibly while an earlier candidate was in flight):
	// do not enter the resilience stack at all — no bulkhead slot held, no
	// breaker sample recorded, no provider dialed.
	if err := callerAborted(ctx); err != nil {
		return nil, err
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
		return nil, attributeCtxErr(ctx, err)
	}
	if !usageOK(resp) {
		return nil, provider.ErrUsageMissing
	}
	return resp, nil
}

// callerAborted returns the abort sentinel (wrapping the context cause) when
// ctx is already done, else nil. Used both as a pre-flight gate and as the
// attribution verdict for a context error observed during a call.
func callerAborted(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", errCallerAborted, err)
	}
	return nil
}

// attributeCtxErr decides WHOSE deadline fired for a context error raised by an
// egress call, because the two cases have opposite verdicts:
//
//   - the CALLER's context is done → an inherited cancellation. The provider is
//     NOT at fault: it must not be blamed in the log, must not be reported as
//     provider_unavailable, and must not count toward the circuit breaker or a
//     model cooldown. Becomes errCallerAborted.
//   - the caller's context is fine → the only other clock in play is the
//     broker's OWN CallTimeoutSec deadline (set in guard), i.e. the provider outran
//     the time we allow it. That is a genuine provider timeout, so the error is
//     passed through unchanged and keeps its provider_unavailable (retriable)
//     classification.
//
// Comparing the PARENT context's Err() is what makes them distinguishable:
// ctx.Err() on the DERIVED context reports Canceled/DeadlineExceeded in both
// cases (a parent cancellation propagates into the child), so the derived
// context alone cannot attribute blame. The parent reports an error only when
// the caller actually went away — which is exactly the signal we need, and it
// needs no extra bookkeeping or pre-call snapshot.
func attributeCtxErr(caller context.Context, err error) error {
	if !isCtxErr(err) {
		return err
	}
	if abort := callerAborted(caller); abort != nil {
		return abort
	}
	return err
}

// isCtxErr reports whether err is, or wraps, a context cancellation/deadline.
// The adapters surface these RAW (provider.transportError) precisely so this
// classification is possible.
func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
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

// guard composes the resilience wrappers around fn (§9). The PER-PROVIDER
// bulkhead admits the call first, queueing for a slot when every one is busy;
// only THEN does the broker's own per-call deadline start, so queueing never
// eats into the time the BROKER allows the provider. It cannot do the same for
// the caller: the caller's own timeout (an agent's batch wait and socket read
// timeout, the judge's per-request timeout) runs from when it sent the request
// and still includes the queue. Inside the slot the PER-(provider,model)
// breaker fails over on open and the retrier applies the retry budget (its
// backoff counts against the deadline). A caller that leaves while queued gets
// its context error back without the breaker ever seeing it.
func (s *Server) guard(ctx context.Context, providerKey, breakerKey string, fn func(context.Context) error) error {
	return s.deps.Bulkheads.For(providerKey).Execute(ctx, func(admitted context.Context) error {
		callCtx, cancel := s.withCallDeadline(admitted)
		defer cancel()
		return s.deps.Breakers.For(breakerKey).Execute(callCtx, func(c context.Context) error {
			return s.deps.Retriers.For(providerKey).Execute(c, fn)
		})
	})
}

// withCallDeadline bounds ONE admitted provider call (§9/§16) so a hung or slow
// provider cannot hold the goroutine, bulkhead slot and budget lease
// indefinitely. CallTimeoutSec <= 0 disables the guard (test default).
func (s *Server) withCallDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.deps.CallTimeoutSec <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, s.callTimeout())
}

// usageOK enforces the usage-sanity floor: a clean completion must be present
// and report a non-zero token count, never $0/zero usage (§11) — EXCEPT when the
// adapter marked the usage Estimated (§32.1 #5: a keyless/local $0 endpoint that
// omitted its meter is a legitimate completion, not a billing risk).
func usageOK(resp *provider.CompletionResponse) bool {
	return resp != nil && (resp.Usage.InputTokens > 0 || resp.Usage.OutputTokens > 0 || resp.Usage.Estimated)
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
		HasTemperature: req.HasTemperature,
		Stream:         false,
		RequestID:      req.RequestID,
	}
}

// noteOverflow tells the broker an upstream call overflowed the model's
// context (0074 #12): the window it was sized for may be stale.
func (s *Server) noteOverflow(err error) {
	if s.deps.OnContextOverflow != nil && errors.Is(err, provider.ErrContextOverflow) {
		s.deps.OnContextOverflow()
	}
}
