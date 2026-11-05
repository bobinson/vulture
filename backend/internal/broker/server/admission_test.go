// Admission contract for the broker's per-provider bulkhead. A request that
// finds every provider slot busy QUEUES for one rather than being answered
// rate_limited at once, and the queue must cost the request nothing the broker
// controls:
//   - the broker's own per-call deadline (VULTURE_LLM_CALL_TIMEOUT_SEC) starts
//     when the request is ADMITTED, so queueing never eats into it (a caller's
//     OWN timeout still counts the queue — the broker cannot change that);
//   - the budget lease is sized to outlive the queue AND the call, so it cannot
//     be swept (and its reservation re-spent) while the request is still alive;
//   - a request that FAILS hands its lease straight back: only a success is
//     ever reconciled, so a failed request's lease would be returned uncharged
//     by the sweeper anyway, and holding it until then only blocks a capped
//     budget;
//   - a caller that leaves while queued is request_aborted on both endpoints;
//   - a rate_limited answer carries Retry-After so a client backs off instead
//     of re-hammering a saturated broker.
package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/resilience"
	"github.com/vulture/backend/internal/broker/server"
	"github.com/vulture/backend/internal/broker/token"
)

// --- concurrency-safe doubles (the shared harness fakes record unguarded) ---

type staticVerifier struct{ claims *token.Claims }

func (v staticVerifier) Verify(string) (*token.Claims, error) { return v.claims, nil }

type staticSSRF struct{}

func (staticSSRF) Validate(prov, baseURL string) (*egress.PinnedTarget, error) {
	return &egress.PinnedTarget{URL: baseURL, IP: "203.0.113.10", Provider: prov}, nil
}

type staticSelector struct{ sel *egress.ModelSelection }

func (s staticSelector) Select(string, egress.PolicyContext) (*egress.ModelSelection, error) {
	return s.sel, nil
}

// adapterEntry is what a slotAdapter saw when a call reached it.
type adapterEntry struct {
	requestID string
	at        time.Time
	left      time.Duration // remaining per-call deadline at entry; 0 = none
}

// slotAdapter holds its provider slot for `hold` (or, when hold is 0, until
// release is called), recording each entry. It answers a well-formed
// completion unless its ctx ends first.
type slotAdapter struct {
	hold    time.Duration
	gate    chan struct{}
	entered chan struct{}

	mu      sync.Mutex
	entries []adapterEntry
	once    sync.Once
}

func newSlotAdapter(hold time.Duration) *slotAdapter {
	return &slotAdapter{hold: hold, gate: make(chan struct{}), entered: make(chan struct{}, 16)}
}

func (a *slotAdapter) release() { a.once.Do(func() { close(a.gate) }) }

func (a *slotAdapter) Name() string { return "openai" }

func (a *slotAdapter) record(ctx context.Context, requestID string) {
	e := adapterEntry{requestID: requestID, at: time.Now()}
	if dl, ok := ctx.Deadline(); ok {
		e.left = time.Until(dl)
	}
	a.mu.Lock()
	a.entries = append(a.entries, e)
	a.mu.Unlock()
	a.entered <- struct{}{}
}

func (a *slotAdapter) Complete(ctx context.Context, _ provider.Credentials, req provider.CompletionRequest) (*provider.CompletionResponse, error) {
	a.record(ctx, req.RequestID)
	if err := a.wait(ctx); err != nil {
		return nil, err
	}
	return &provider.CompletionResponse{
		Model: req.Model, Provider: "openai", Content: "ok", FinishReason: "stop",
		Usage: provider.Usage{InputTokens: 3, OutputTokens: 2}, RequestID: req.RequestID,
	}, nil
}

func (a *slotAdapter) wait(ctx context.Context) error {
	var timer <-chan time.Time
	if a.hold > 0 {
		timer = time.After(a.hold)
	}
	select {
	case <-timer:
		return nil
	case <-a.gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *slotAdapter) Stream(context.Context, provider.Credentials, provider.CompletionRequest) (<-chan provider.StreamChunk, error) {
	return nil, provider.ErrNotImplemented
}

func (a *slotAdapter) Embed(ctx context.Context, _ provider.Credentials, req provider.EmbeddingRequest) (*provider.EmbeddingResponse, error) {
	a.record(ctx, req.RequestID)
	if err := a.wait(ctx); err != nil {
		return nil, err
	}
	return &provider.EmbeddingResponse{
		Model: req.Model, Provider: "openai", Embeddings: [][]float32{{0.1}},
		Usage: provider.Usage{InputTokens: 2}, RequestID: req.RequestID,
	}, nil
}

func (a *slotAdapter) entryFor(t *testing.T, requestID string) adapterEntry {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if e.requestID == requestID {
			return e
		}
	}
	t.Fatalf("request %s never reached the provider", requestID)
	return adapterEntry{}
}

func (a *slotAdapter) calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.entries)
}

func awaitEntered(t *testing.T, a *slotAdapter) {
	t.Helper()
	select {
	case <-a.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("request never reached the provider")
	}
}

// queueServer wires the healthy harness to a REAL single-slot bulkhead (so a
// second request queues) and race-free doubles, with the given admission bound
// and per-call timeout.
func queueServer(h *harness, a *slotAdapter, maxWait time.Duration, callTimeoutSec int) *server.Server {
	h.adapters["openai"] = a
	deps := h.deps()
	deps.Verifier = staticVerifier{claims: h.verifier.claims}
	deps.SSRF = staticSSRF{}
	deps.Selector = staticSelector{sel: &egress.ModelSelection{Model: "gpt-4o"}}
	deps.Bulkheads = resilience.NewBulkheadPool(resilience.BulkheadConfig{MaxConcurrent: 1, MaxWait: maxWait})
	deps.CallTimeoutSec = callTimeoutSec
	return server.New(deps)
}

func bodyFor(requestID string) map[string]any {
	b := completeBody()
	b["request_id"] = requestID
	return b
}

type postResult struct {
	rr  *httptest.ResponseRecorder
	end time.Time
}

func postAsync(t *testing.T, srv *server.Server, ctx context.Context, requestID string) <-chan postResult {
	return postPathAsync(t, srv, ctx, completePath, bodyFor(requestID))
}

// postPathAsync posts body to path on a caller-supplied context (doPostCtx is
// completions-only), returning the result on a channel.
func postPathAsync(t *testing.T, srv *server.Server, ctx context.Context, path string, body map[string]any) <-chan postResult {
	out := make(chan postResult, 1)
	go func() {
		oa, taskType, requestID := toOpenAIBody(body)
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(oa); err != nil {
			t.Errorf("encode body: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, path, &buf).WithContext(ctx)
		req.Header.Set("Authorization", testBearer)
		req.Header.Set("Content-Type", "application/json")
		if taskType != nil {
			req.Header.Set("X-Vulture-Task-Type", *taskType)
		}
		if requestID != nil {
			req.Header.Set("X-Vulture-Request-Id", *requestID)
		}
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		out <- postResult{rr: rr, end: time.Now()}
	}()
	return out
}

func awaitResult(t *testing.T, ch <-chan postResult) postResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("request did not complete")
		return postResult{}
	}
}

func retryAfterSeconds(t *testing.T, rr *httptest.ResponseRecorder) int {
	t.Helper()
	v := rr.Header().Get("Retry-After")
	if v == "" {
		t.Fatalf("rate_limited answer has no Retry-After header; body=%q", rr.Body.String())
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		t.Fatalf("Retry-After = %q, want a positive number of seconds", v)
	}
	return n
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// --- the queue ---

// The defect: a request arriving while every slot was busy was answered 429 at
// once. It must instead wait and be served when a slot frees.
func TestHandleComplete_QueuedRequestIsServedWhenASlotFrees(t *testing.T) {
	a := newSlotAdapter(0)
	srv := queueServer(newHealthyHarness(), a, 0, 0)

	first := postAsync(t, srv, context.Background(), "req-A")
	awaitEntered(t, a)
	second := postAsync(t, srv, context.Background(), "req-B")

	select {
	case r := <-second:
		t.Fatalf("queued request answered %d while the slot was held; it must wait (body=%q)", r.rr.Code, r.rr.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	if got := a.calls(); got != 1 {
		t.Fatalf("provider calls while one request holds the only slot = %d, want 1", got)
	}

	a.release()
	for _, ch := range []<-chan postResult{first, second} {
		if r := awaitResult(t, ch); r.rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 once a slot freed; body=%q", r.rr.Code, r.rr.Body.String())
		}
	}
	if got := a.calls(); got != 2 {
		t.Fatalf("provider calls = %d, want 2 (the queued request was served)", got)
	}
}

// The broker's per-call deadline must start at ADMISSION. Started before the
// wait, a request queued behind a long call reaches the provider with only the
// leftover of its timeout and is cut off mid-generation — and blamed on the
// provider (provider_unavailable). (The caller's own timeout is its own and
// still runs from when it sent the request.)
func TestHandleComplete_CallDeadlineStartsAfterAdmission(t *testing.T) {
	const hold = 600 * time.Millisecond
	a := newSlotAdapter(hold)
	srv := queueServer(newHealthyHarness(), a, 0, 1) // 1 s per-call timeout

	first := postAsync(t, srv, context.Background(), "req-A")
	awaitEntered(t, a)
	queuedAt := time.Now()
	second := postAsync(t, srv, context.Background(), "req-B")

	for _, ch := range []<-chan postResult{first, second} {
		if r := awaitResult(t, ch); r.rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (a %v call fits a 1 s timeout); body=%q", r.rr.Code, hold, r.rr.Body.String())
		}
	}
	b := a.entryFor(t, "req-B")
	if waited := b.at.Sub(queuedAt); waited < hold/2 {
		t.Fatalf("req-B reached the provider after %v: it never queued, so the test proves nothing", waited)
	}
	if b.left < 800*time.Millisecond {
		t.Fatalf("req-B reached the provider with %v of its 1 s call timeout left: the queue wait was charged to the call", b.left)
	}
}

// A caller that leaves while queued is answered request_aborted (not a provider
// fault, never a breaker sample), and its lease is handed back at once.
func TestHandleComplete_CallerLeavesWhileQueued_AbortsAndReleasesLease(t *testing.T) {
	a := newSlotAdapter(0)
	h := newHealthyHarness()
	cb := &countingBreaker{}
	h.keyedBreakers = map[string]resilience.CircuitBreaker{"openai:gpt-4o": cb}
	srv := queueServer(h, a, 0, 0)

	first := postAsync(t, srv, context.Background(), "req-A")
	awaitEntered(t, a)
	ctx, cancel := context.WithCancel(context.Background())
	second := postAsync(t, srv, ctx, "req-B")
	time.Sleep(50 * time.Millisecond) // req-B is queued behind req-A
	cancel()

	r := awaitResult(t, second)
	if r.rr.Code != statusClientClosed {
		t.Fatalf("status = %d, want %d for a caller that left while queued; body=%q", r.rr.Code, statusClientClosed, r.rr.Body.String())
	}
	if got := decodeErr(t, r.rr).Error.Code; got != "request_aborted" {
		t.Fatalf("code = %q, want request_aborted", got)
	}
	if got := a.calls(); got != 1 {
		t.Fatalf("provider calls = %d, want 1 (the abandoned request never egressed)", got)
	}
	if got := atomic.LoadInt32(&cb.execs); got != 1 {
		t.Fatalf("breaker samples = %d, want 1 (a queued abort is not a provider sample)", got)
	}
	if !contains(h.budget.releasedRequests(), "req-B") {
		t.Fatalf("released = %v, want req-B's lease handed back", h.budget.releasedRequests())
	}

	a.release()
	if r := awaitResult(t, first); r.rr.Code != http.StatusOK {
		t.Fatalf("holder status = %d, want 200", r.rr.Code)
	}
	if contains(h.budget.releasedRequests(), "req-A") {
		t.Fatal("a served request's lease must be reconciled, not released")
	}
}

// The admission bound: a request that cannot get a slot within it is shed as
// rate_limited (the broker's own queue limit, not a provider fault), with
// Retry-After, and its lease is handed back.
func TestHandleComplete_QueueTimeoutIsRateLimitedAndReleasesLease(t *testing.T) {
	a := newSlotAdapter(0)
	h := newHealthyHarness()
	srv := queueServer(h, a, 50*time.Millisecond, 0)

	first := postAsync(t, srv, context.Background(), "req-A")
	awaitEntered(t, a)
	r := awaitResult(t, postAsync(t, srv, context.Background(), "req-B"))

	if r.rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 after the admission bound; body=%q", r.rr.Code, r.rr.Body.String())
	}
	if got := decodeErr(t, r.rr).Error.Code; got != "rate_limited" {
		t.Fatalf("code = %q, want rate_limited", got)
	}
	retryAfterSeconds(t, r.rr)
	if !contains(h.budget.releasedRequests(), "req-B") {
		t.Fatalf("released = %v, want req-B's lease handed back", h.budget.releasedRequests())
	}
	a.release()
	awaitResult(t, first)
}

// --- leases ---

func TestHandleComplete_ShedReleasesLeaseAndAdvisesRetryAfter(t *testing.T) {
	h := newHealthyHarness()
	h.bulkhead.forceErr = resilience.ErrBulkheadFull

	rr := doPost(t, h.server(), completePath, testBearer, completeBody())

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body=%q", rr.Code, rr.Body.String())
	}
	retryAfterSeconds(t, rr)
	if got := h.budget.releasedRequests(); len(got) != 1 || got[0] != "req-1" {
		t.Fatalf("released = %v, want exactly req-1 (a shed request never egressed)", got)
	}
}

// Only a success is ever reconciled, so a FAILED request's lease would be
// returned uncharged by the sweeper whatever happened — holding it until then
// only blocks a capped budget. Every failure hands it back at once, including
// those after the call reached the provider.
func TestHandleComplete_FailedRequestReleasesLease(t *testing.T) {
	cases := []struct {
		name string
		err  error
		resp *provider.CompletionResponse
	}{
		{"provider rejected the request", provider.ErrProviderBadRequest, nil},
		{"provider unavailable", provider.ErrProviderUnavailable, nil},
		{"upstream rate limit", provider.ErrRateLimited, nil},
		{"usage missing", nil, &provider.CompletionResponse{Model: "gpt-4o", Provider: "openai", Content: "x"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHealthyHarness()
			h.selector.sel = &egress.ModelSelection{Model: "gpt-4o"}
			h.openaiFake.resp = c.resp
			h.openaiFake.err = c.err

			rr := doPost(t, h.server(), completePath, testBearer, completeBody())

			if rr.Code == http.StatusOK {
				t.Fatalf("status = 200, want a failure")
			}
			if h.openaiFake.completeReq == nil {
				t.Fatal("precondition: the call must have reached the provider")
			}
			if got := h.budget.releasedRequests(); len(got) != 1 || got[0] != "req-1" {
				t.Fatalf("released = %v, want exactly req-1", got)
			}
			if n := len(h.budget.reconciledEntries()); n != 0 {
				t.Fatalf("reconciled %d entries for a failed request, want 0", n)
			}
		})
	}
}

func TestHandleComplete_OpenCircuitReleasesLease(t *testing.T) {
	h := newHealthyHarness()
	h.selector.sel = &egress.ModelSelection{Model: "gpt-4o"}
	h.breaker.forceErr = resilience.ErrCircuitOpen

	if rr := doPost(t, h.server(), completePath, testBearer, completeBody()); rr.Code == http.StatusOK {
		t.Fatalf("status = 200, want a failure")
	}
	if got := h.budget.releasedRequests(); len(got) != 1 || got[0] != "req-1" {
		t.Fatalf("released = %v, want exactly req-1", got)
	}
}

func TestHandleComplete_BrokerCallTimeoutReleasesLease(t *testing.T) {
	a := &ctxAdapter{name: "openai", block: true}
	h, _ := cancelHarness(a)
	deps := h.deps()
	deps.CallTimeoutSec = 1

	rr := doPostCtx(t, server.New(deps), context.Background(), completeBody())

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (the broker's own deadline fired); body=%q", rr.Code, rr.Body.String())
	}
	if got := h.budget.releasedRequests(); len(got) != 1 || got[0] != "req-1" {
		t.Fatalf("released = %v, want exactly req-1", got)
	}
}

func TestHandleComplete_CallerLeavingMidCallReleasesLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &ctxAdapter{name: "openai", before: cancel, err: context.Canceled}
	h, _ := cancelHarness(a)

	rr := doPostCtx(t, h.server(), ctx, completeBody())

	if rr.Code != statusClientClosed {
		t.Fatalf("status = %d, want %d; body=%q", rr.Code, statusClientClosed, rr.Body.String())
	}
	if got := h.budget.releasedRequests(); len(got) != 1 || got[0] != "req-1" {
		t.Fatalf("released = %v, want exactly req-1", got)
	}
}

func TestHandleComplete_SuccessReconcilesAndDoesNotRelease(t *testing.T) {
	h := newHealthyHarness()
	if rr := doPost(t, h.server(), completePath, testBearer, completeBody()); rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if n := len(h.budget.reconciledEntries()); n != 1 {
		t.Fatalf("reconciled %d entries, want 1", n)
	}
	if got := h.budget.releasedRequests(); len(got) != 0 {
		t.Fatalf("released = %v, want none on success (reconcile settles the lease)", got)
	}
}

// The lease must outlive everything the request can still do: for each
// candidate it may try, a wait of up to the admission bound for a slot and then
// a call of up to the call timeout. The fixed two-minute lease expired under a
// 439 s call, letting the sweeper return a live reservation to the cap.
func TestHandleComplete_LeaseOutlivesQueueAndCall(t *testing.T) {
	const callTimeoutSec = 439
	perCandidate := server.AdmissionWait(callTimeoutSec) + callTimeoutSec*time.Second
	cases := []struct {
		name       string
		sel        *egress.ModelSelection
		candidates int
	}{
		{"single candidate", &egress.ModelSelection{Model: "gpt-4o"}, 1},
		{"with a fallback", &egress.ModelSelection{Model: "gpt-4o", Fallbacks: []string{"gpt-4o-mini"}}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHealthyHarness()
			h.selector.sel = c.sel
			deps := h.deps()
			deps.CallTimeoutSec = callTimeoutSec
			if rr := doPost(t, server.New(deps), completePath, testBearer, completeBody()); rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
			}
			reqs := h.budget.reserveRequests()
			if len(reqs) != 1 {
				t.Fatalf("reservations = %d, want 1", len(reqs))
			}
			if want := time.Duration(c.candidates) * perCandidate; reqs[0].LeaseTTL < want {
				t.Fatalf("LeaseTTL = %v, want >= %v (queue + call for each of %d candidates)", reqs[0].LeaseTTL, want, c.candidates)
			}
		})
	}
}

func TestAdmissionWait_IsOneCallTimeout(t *testing.T) {
	if got := server.AdmissionWait(439); got != 439*time.Second {
		t.Fatalf("AdmissionWait(439) = %v, want 439s", got)
	}
	if got := server.AdmissionWait(0); got != 0 {
		t.Fatalf("AdmissionWait(0) = %v, want 0 (no call timeout: bounded by the request context)", got)
	}
}

// --- Retry-After ---

func TestHandleComplete_UpstreamRateLimitAdvisesRetryAfter(t *testing.T) {
	h := newHealthyHarness()
	h.openaiFake.resp = nil
	h.openaiFake.err = provider.ErrRateLimited

	rr := doPost(t, h.server(), completePath, testBearer, completeBody())

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body=%q", rr.Code, rr.Body.String())
	}
	retryAfterSeconds(t, rr)
}

func TestHandleComplete_OtherErrorsCarryNoRetryAfter(t *testing.T) {
	h := newHealthyHarness()
	h.openaiFake.resp = nil
	h.openaiFake.err = provider.ErrProviderUnavailable
	h.selector.sel = &egress.ModelSelection{Model: "gpt-4o"}

	rr := doPost(t, h.server(), completePath, testBearer, completeBody())

	if rr.Code == http.StatusTooManyRequests || rr.Code == http.StatusOK {
		t.Fatalf("status = %d, want a provider error", rr.Code)
	}
	if v := rr.Header().Get("Retry-After"); v != "" {
		t.Fatalf("Retry-After = %q on a %d; it belongs to rate_limited only", v, rr.Code)
	}
}

// --- embeddings share the admission contract ---

func embedHarness() (*harness, map[string]any) {
	h := newHealthyHarness()
	h.verifier.claims.Scope = []string{"embed:text-embedding-3-small"}
	h.openaiFake.embedResp = &provider.EmbeddingResponse{
		Model: "text-embedding-3-small", Provider: "openai",
		Embeddings: [][]float32{{0.1}}, Usage: provider.Usage{InputTokens: 2, CostUSD: 0.00001},
	}
	return h, map[string]any{"model": "text-embedding-3-small", "request_id": "emb-1", "inputs": []string{"x"}}
}

func TestHandleEmbed_LeaseOutlivesQueueAndCall(t *testing.T) {
	const callTimeoutSec = 439
	h, body := embedHarness()
	deps := h.deps()
	deps.CallTimeoutSec = callTimeoutSec
	if rr := doPost(t, server.New(deps), embedPath, testBearer, body); rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	reqs := h.budget.reserveRequests()
	want := server.AdmissionWait(callTimeoutSec) + callTimeoutSec*time.Second
	if len(reqs) != 1 || reqs[0].LeaseTTL < want {
		t.Fatalf("embed reservations = %+v, want one with LeaseTTL >= %v", reqs, want)
	}
}

func TestHandleEmbed_ShedReleasesLeaseAndAdvisesRetryAfter(t *testing.T) {
	h, body := embedHarness()
	h.bulkhead.forceErr = resilience.ErrBulkheadFull

	rr := doPost(t, h.server(), embedPath, testBearer, body)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body=%q", rr.Code, rr.Body.String())
	}
	retryAfterSeconds(t, rr)
	if got := h.budget.releasedRequests(); len(got) != 1 || got[0] != "emb-1" {
		t.Fatalf("released = %v, want exactly emb-1", got)
	}
}

func TestHandleEmbed_FailedRequestReleasesLease(t *testing.T) {
	h, body := embedHarness()
	h.openaiFake.embedResp = nil
	h.openaiFake.embedErr = provider.ErrProviderUnavailable

	if rr := doPost(t, h.server(), embedPath, testBearer, body); rr.Code == http.StatusOK {
		t.Fatalf("status = 200, want a failure")
	}
	if got := h.budget.releasedRequests(); len(got) != 1 || got[0] != "emb-1" {
		t.Fatalf("released = %v, want exactly emb-1", got)
	}
}

// An embeddings caller that leaves while queued is attributed like a
// completion caller: request_aborted (499), never provider_unavailable, and no
// breaker sample — the provider did nothing wrong.
func TestHandleEmbed_CallerLeavesWhileQueued_IsRequestAborted(t *testing.T) {
	a := newSlotAdapter(0)
	h, _ := embedHarness()
	cb := &countingBreaker{}
	h.keyedBreakers = map[string]resilience.CircuitBreaker{"openai:text-embedding-3-small": cb}
	srv := queueServer(h, a, 0, 0)
	embedBody := func(id string) map[string]any {
		return map[string]any{"model": "text-embedding-3-small", "request_id": id, "inputs": []string{"x"}}
	}

	first := postPathAsync(t, srv, context.Background(), embedPath, embedBody("emb-A"))
	awaitEntered(t, a)
	ctx, cancel := context.WithCancel(context.Background())
	second := postPathAsync(t, srv, ctx, embedPath, embedBody("emb-B"))
	time.Sleep(50 * time.Millisecond) // emb-B is queued behind emb-A
	cancel()

	r := awaitResult(t, second)
	if r.rr.Code != statusClientClosed {
		t.Fatalf("status = %d, want %d for an embeddings caller that left while queued; body=%q", r.rr.Code, statusClientClosed, r.rr.Body.String())
	}
	if got := decodeErr(t, r.rr).Error.Code; got != "request_aborted" {
		t.Fatalf("code = %q, want request_aborted", got)
	}
	if got := atomic.LoadInt32(&cb.execs); got != 1 {
		t.Fatalf("breaker samples = %d, want 1 (a queued abort is not a provider sample)", got)
	}
	if !contains(h.budget.releasedRequests(), "emb-B") {
		t.Fatalf("released = %v, want emb-B's lease handed back", h.budget.releasedRequests())
	}
	a.release()
	if r := awaitResult(t, first); r.rr.Code != http.StatusOK {
		t.Fatalf("holder status = %d, want 200; body=%q", r.rr.Code, r.rr.Body.String())
	}
}
