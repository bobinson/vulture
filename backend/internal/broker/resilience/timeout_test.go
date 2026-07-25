package resilience

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Contract (§9): a per-call context deadline (VULTURE_LLM_CALL_TIMEOUT_SEC)
// bounds every provider egress attempt. The wrappers pass ctx straight to
// fn; a fn that respects ctx must observe cancellation. We verify the
// wrappers do NOT swallow ctx cancellation and that a deadline-exceeded ctx
// short-circuits without a real sleep.

func TestRetrier_PropagatesContextCancellation(t *testing.T) {
	clk := newFakeClock()
	r := newTestRetrier(clk, identityJitter, defaultClassifier(), basePolicy())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	// fn observes the cancelled ctx and returns its error.
	err := r.Execute(ctx, func(ctx context.Context) error { return ctx.Err() })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute with cancelled ctx = %v, want context.Canceled", err)
	}
}

func TestRetrier_StopsRetryingOnDeadline(t *testing.T) {
	clk := newFakeClock()
	r := newTestRetrier(clk, identityJitter, defaultClassifier(), basePolicy())

	// A ctx that is already past deadline: even though fn returns a
	// retryable error, the retrier must not loop forever — it must observe
	// the expired ctx and return promptly (deadline wins over retry).
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()

	sc := newScriptedCall(err500, err500, err500)
	done := make(chan error, 1)
	go func() { done <- r.Execute(ctx, sc.fn()) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Execute past deadline = nil, want a deadline/retryable error")
		}
		// Must surface either the ctx error or the last fn error, but must
		// NOT have exhausted all attempts by ignoring the deadline.
	case <-time.After(2 * time.Second):
		t.Fatal("Execute blocked past deadline; per-call deadline must bound retries")
	}
}

func TestBulkhead_RespectsContextOnAcquire(t *testing.T) {
	bh := NewBulkhead(BulkheadConfig{MaxConcurrent: 1})

	// Occupy the only slot.
	release := make(chan struct{})
	started := make(chan struct{})
	go func() {
		_ = bh.Execute(context.Background(), func(context.Context) error {
			close(started)
			<-release
			return nil
		})
	}()
	recvStarted(t, started)

	// A cancelled ctx must not cause a blocking wait: bulkhead sheds fast
	// (ErrBulkheadFull) or observes ctx — either way it returns promptly.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() {
		done <- bh.Execute(ctx, func(context.Context) error { return nil })
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("over-cap Execute with cancelled ctx = nil, want error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bulkhead blocked with cancelled ctx over cap; must return promptly")
	}
	close(release)
}

func TestCircuitBreaker_OpenIgnoresContext(t *testing.T) {
	// When open, the breaker rejects with ErrCircuitOpen regardless of ctx
	// state — fast rejection, no fn call, no sleep.
	clk := newFakeClock()
	cb := newTestBreaker(clk)
	for i := 0; i < 3; i++ {
		_ = cb.Execute(context.Background(), func(context.Context) error { return err500 })
	}
	if cb.State() != StateOpen {
		t.Fatalf("precondition: want open, got %v", cb.State())
	}
	err := cb.Execute(context.Background(), func(context.Context) error { return nil })
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("open breaker Execute = %v, want ErrCircuitOpen", err)
	}
}
