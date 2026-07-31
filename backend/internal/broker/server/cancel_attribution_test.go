// Cancellation-attribution contract tests for the egress loop (feature 0070
// P5, defect B). A request the CALLER abandoned must never be reported —
// client-facing or in the log — as a provider failure, and must not consume a
// bulkhead slot / breaker sample / budget reservation on the way out. The
// broker's OWN call deadline is the opposite case: the provider took longer
// than we allow, so the provider IS at fault and keeps its
// provider_unavailable classification.
package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/resilience"
	"github.com/vulture/backend/internal/broker/server"
)

// statusClientClosed is the client-closed-request status the abort surfaces
// (nginx's 499; net/http has no constant for it).
const statusClientClosed = 499

// ctxAdapter reproduces the real adapters' transport contract for a
// cancelled/expired context: provider.transportError surfaces the RAW context
// error (never wrapped in ErrProviderUnavailable). before() runs first so a
// test can cancel the caller mid-call; block waits for the ctx to expire and
// then returns its error.
type ctxAdapter struct {
	name   string
	before func()
	err    error
	block  bool
	calls  int32
}

func (a *ctxAdapter) Name() string { return a.name }

func (a *ctxAdapter) Complete(ctx context.Context, creds provider.Credentials, req provider.CompletionRequest) (*provider.CompletionResponse, error) {
	atomic.AddInt32(&a.calls, 1)
	if a.before != nil {
		a.before()
	}
	if a.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, a.err
}

func (a *ctxAdapter) Stream(ctx context.Context, creds provider.Credentials, req provider.CompletionRequest) (<-chan provider.StreamChunk, error) {
	return nil, provider.ErrNotImplemented
}

func (a *ctxAdapter) Embed(ctx context.Context, creds provider.Credentials, req provider.EmbeddingRequest) (*provider.EmbeddingResponse, error) {
	return nil, provider.ErrNotImplemented
}

func (a *ctxAdapter) callCount() int { return int(atomic.LoadInt32(&a.calls)) }

// countingBreaker counts the samples the breaker is asked to take and
// classifies each with the PRODUCTION classifier (provider.IsProviderHealthFailure,
// wired in serve.breakerCountsAsFailure) so a test can assert what the real
// per-(provider,model) breaker would do with the error the egress loop
// produced.
type countingBreaker struct {
	execs    int32
	failures int32
}

func (b *countingBreaker) Execute(ctx context.Context, fn resilience.Call) error {
	atomic.AddInt32(&b.execs, 1)
	err := fn(ctx)
	if provider.IsProviderHealthFailure(err) {
		atomic.AddInt32(&b.failures, 1)
	}
	return err
}

func (b *countingBreaker) State() resilience.CircuitState { return resilience.StateClosed }

var _ resilience.CircuitBreaker = (*countingBreaker)(nil)

// cancelHarness wires the healthy harness with a context-error adapter for
// openai and a counting breaker, returning both.
func cancelHarness(a *ctxAdapter) (*harness, *countingBreaker) {
	h := newHealthyHarness()
	h.adapters["openai"] = a
	cb := &countingBreaker{}
	h.keyedBreakers = map[string]resilience.CircuitBreaker{"openai:gpt-4o": cb}
	return h, cb
}

// doPostCtx is doPost with a caller-supplied request context so a test can
// cancel the in-flight request (doPost always uses a background context).
func doPostCtx(t *testing.T, srv *server.Server, ctx context.Context, body any) *httptest.ResponseRecorder {
	t.Helper()
	oa, taskType, requestID := toOpenAIBody(body)
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(oa); err != nil {
		t.Fatalf("encode body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, completePath, &buf).WithContext(ctx)
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
	return rr
}

// wireRetriable reads the retriable hint off the OpenAI-shaped error envelope.
// NOTE: the shared errorEnvelope helper decodes `retriable`, but the wire field
// is `x_retriable` (see writeErr) — so it always reads false. Decode it here
// rather than editing the shared helper.
func wireRetriable(t *testing.T, rr *httptest.ResponseRecorder) bool {
	t.Helper()
	var env struct {
		Error struct {
			Retriable bool `json:"x_retriable"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope from %q: %v", rr.Body.String(), err)
	}
	return env.Error.Retriable
}

// captureLog redirects the standard logger for the duration of fn and returns
// what was written (the broker logs egress causes through log.Printf).
func captureLog(fn func()) string {
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}()
	fn()
	return buf.String()
}

// B.3: a caller that cancels mid-call gets a DISTINCT, non-retriable typed
// error — "we gave up" must not be reported as "they were down", because the
// two warrant different retry behavior on the agent side.
func TestHandleComplete_CallerCancelledMidCall_DistinctAbortError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &ctxAdapter{name: "openai", before: cancel, err: context.Canceled}
	h, cb := cancelHarness(a)

	rr := doPostCtx(t, h.server(), ctx, completeBody())

	if rr.Code != statusClientClosed {
		t.Fatalf("status = %d, want %d (caller cancellation is not a provider fault); body=%q",
			rr.Code, statusClientClosed, rr.Body.String())
	}
	env := decodeErr(t, rr)
	if env.Error.Code == "provider_unavailable" || env.Error.Code == "all_providers_down" {
		t.Fatalf("code = %q: a caller cancellation was blamed on the provider", env.Error.Code)
	}
	if env.Error.Code != "request_aborted" {
		t.Fatalf("code = %q, want request_aborted", env.Error.Code)
	}
	if wireRetriable(t, rr) {
		t.Fatalf("retriable = true: retrying a request the caller abandoned is pointless")
	}
	// §26/N6: the abort surface stays secret-free.
	assertNoSecretLeak(t, rr.Body.String())
	if got := int(atomic.LoadInt32(&cb.failures)); got != 0 {
		t.Fatalf("breaker recorded %d provider-health failures for a caller cancellation, want 0", got)
	}
}

// B.2: the log must attribute the abort to the caller. `egress failed
// provider=` blames a provider that did nothing wrong and sends an operator
// hunting a phantom outage.
func TestHandleComplete_CallerCancelled_LogsAbortNotProviderFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &ctxAdapter{name: "openai", before: cancel, err: context.Canceled}
	h, _ := cancelHarness(a)
	srv := h.server()

	out := captureLog(func() { doPostCtx(t, srv, ctx, completeBody()) })

	if strings.Contains(out, "egress failed provider=") {
		t.Fatalf("log blames the provider for a caller cancellation: %q", out)
	}
	if !strings.Contains(out, "egress aborted") || !strings.Contains(out, "caller cancelled") {
		t.Fatalf("log = %q, want an abort line naming the caller as the cause", out)
	}
	if !strings.Contains(out, "provider=openai") || !strings.Contains(out, "model=gpt-4o") {
		t.Fatalf("abort log = %q, want it to still identify provider+model", out)
	}
	assertNoSecretLeak(t, out)
}

// B.2: a request whose caller is ALREADY gone must not enter the resilience
// stack at all — no bulkhead slot, no breaker sample, no provider dial — and
// must not reserve budget it will never reconcile.
func TestHandleComplete_CallerGoneBeforeEgress_NoProviderCallNoBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := &ctxAdapter{name: "openai", err: context.Canceled}
	h, cb := cancelHarness(a)

	rr := doPostCtx(t, h.server(), ctx, completeBody())

	if a.callCount() != 0 {
		t.Fatalf("adapter was dialed %d times for an already-abandoned request, want 0", a.callCount())
	}
	if got := int(atomic.LoadInt32(&cb.execs)); got != 0 {
		t.Fatalf("breaker took %d samples for an already-abandoned request, want 0", got)
	}
	if n := len(h.budget.reserveRequests()); n != 0 {
		t.Fatalf("budget reserved %d times for an already-abandoned request, want 0 (the lease would never be reconciled)", n)
	}
	if rr.Code != statusClientClosed {
		t.Fatalf("status = %d, want %d; body=%q", rr.Code, statusClientClosed, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "request_aborted" {
		t.Fatalf("code = %q, want request_aborted", got)
	}
}

// B.1: the OTHER side of the attribution split. When the caller's context is
// healthy and the context error came from the broker's own call deadline, the
// provider IS at fault: it keeps provider_unavailable (retriable) and must NOT
// be relabeled a caller abort.
func TestHandleComplete_BrokerDeadline_StillBlamesProvider(t *testing.T) {
	a := &ctxAdapter{name: "openai", err: context.DeadlineExceeded}
	h, _ := cancelHarness(a)

	rr := doPostCtx(t, h.server(), context.Background(), completeBody())

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (a provider that outran our deadline is at fault); body=%q", rr.Code, rr.Body.String())
	}
	env := decodeErr(t, rr)
	if env.Error.Code != "provider_unavailable" {
		t.Fatalf("code = %q, want provider_unavailable", env.Error.Code)
	}
	if !wireRetriable(t, rr) {
		t.Fatalf("retriable = false: a provider timeout is worth retrying")
	}
}

// B.1 end-to-end: the broker's OWN CallTimeoutSec deadline fires (the adapter
// blocks until its ctx expires) while the caller is still waiting. Same
// verdict as above — provider at fault — proving the split keys off WHOSE
// deadline fired, not merely on the error value.
func TestHandleComplete_CallTimeoutFires_BlamesProviderNotCaller(t *testing.T) {
	a := &ctxAdapter{name: "openai", block: true}
	h, _ := cancelHarness(a)
	deps := h.deps()
	deps.CallTimeoutSec = 1
	srv := server.New(deps)

	rr := doPostCtx(t, srv, context.Background(), completeBody())

	if rr.Code == statusClientClosed {
		t.Fatalf("the broker's own call deadline was misattributed to the caller; body=%q", rr.Body.String())
	}
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 provider_unavailable; body=%q", rr.Code, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "provider_unavailable" {
		t.Fatalf("code = %q, want provider_unavailable", got)
	}
}

// B.2/B.3: a caller cancellation must STOP the chain, not walk the fallback
// candidates. Trying every provider on behalf of a caller who has gone away
// burns spend and makes an abort look like a multi-provider outage.
func TestHandleComplete_CallerCancelled_DoesNotFailOverToFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, lm := fallbackHarness()
	primary := &ctxAdapter{name: "openai", before: cancel, err: context.Canceled}
	h.adapters["openai"] = primary

	rr := doPostCtx(t, h.server(), ctx, completeBody())

	if lm.completeReq != nil {
		t.Fatalf("fallback candidate was tried after the caller cancelled")
	}
	if rr.Code != statusClientClosed {
		t.Fatalf("status = %d, want %d; body=%q", rr.Code, statusClientClosed, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got == "all_providers_down" {
		t.Fatalf("caller cancellation reported as all_providers_down")
	}
}

// Guard on the sentinel vocabulary: the abort error must be classifiable with
// errors.Is by the package's own convention, and must wrap the underlying
// context cause so an operator/test can still see WHICH context error fired.
func TestCallerAbortSentinel_WrapsContextCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &ctxAdapter{name: "openai", before: cancel, err: context.Canceled}
	h, _ := cancelHarness(a)

	out := captureLog(func() { doPostCtx(t, h.server(), ctx, completeBody()) })

	if !strings.Contains(out, context.Canceled.Error()) {
		t.Fatalf("abort log = %q, want the underlying context cause preserved", out)
	}
	if !strings.Contains(out, "aborted") {
		t.Fatalf("abort log = %q, want the abort sentinel wrapping the cause", out)
	}
}
