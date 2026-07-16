package resilience

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Contract (§9): per-(provider,model) circuit breaker, per-replica-local.
// closed → (consecutive failures ≥ threshold) → open → (after OpenTimeout)
// → half-open → (probe successes ≥ SuccessThreshold) → closed, or
// (probe failure) → open. Open rejects fast with ErrCircuitOpen, no fn call.

func newTestBreaker(clk Clock) CircuitBreaker {
	return NewCircuitBreaker(CircuitConfig{
		FailureThreshold: 3,
		OpenTimeout:      5 * time.Second,
		HalfOpenMaxCalls: 1,
		SuccessThreshold: 1,
		Clock:            clk,
	})
}

// §32.1 #1: when an IsFailure classifier is set, only provider-health errors
// count toward tripping the breaker. Client-fault / neutral errors are ignored
// (neither trip nor reset) so a bad-request or ctx-cancel cannot open a shared
// (provider,model) breaker and cause a false all_providers_down.
func TestCircuitBreaker_NeutralErrorsDoNotTrip(t *testing.T) {
	neutral := errors.New("neutral-client-fault")
	health := errors.New("provider-health-failure")
	cb := NewCircuitBreaker(CircuitConfig{
		FailureThreshold: 3, OpenTimeout: 5 * time.Second, HalfOpenMaxCalls: 1, SuccessThreshold: 1,
		Clock:     newFakeClock(),
		IsFailure: func(err error) bool { return errors.Is(err, health) },
	})
	// Many neutral errors must never trip.
	for i := 0; i < 10; i++ {
		_ = cb.Execute(context.Background(), func(context.Context) error { return neutral })
	}
	if cb.State() != StateClosed {
		t.Fatalf("neutral errors tripped breaker: %v", cb.State())
	}
	// Neutral errors must not RESET the consecutive-failure counter either:
	// 2 health, 1 neutral, 1 health = 3 health total → trips.
	_ = cb.Execute(context.Background(), func(context.Context) error { return health })
	_ = cb.Execute(context.Background(), func(context.Context) error { return health })
	_ = cb.Execute(context.Background(), func(context.Context) error { return neutral })
	if cb.State() != StateClosed {
		t.Fatalf("breaker tripped early: %v", cb.State())
	}
	_ = cb.Execute(context.Background(), func(context.Context) error { return health })
	if cb.State() != StateOpen {
		t.Fatalf("3 health failures (neutral interleaved) did not trip: %v", cb.State())
	}
}

// Default (no IsFailure classifier) must preserve the legacy behavior: ANY
// non-nil error counts as a failure.
func TestCircuitBreaker_NilClassifierCountsAllErrors(t *testing.T) {
	cb := newTestBreaker(newFakeClock())
	for i := 0; i < 3; i++ {
		_ = cb.Execute(context.Background(), func(context.Context) error { return errors.New("any") })
	}
	if cb.State() != StateOpen {
		t.Fatalf("default breaker must trip on any error, got %v", cb.State())
	}
}

func TestCircuitBreaker_StartsClosed(t *testing.T) {
	cb := newTestBreaker(newFakeClock())
	if got := cb.State(); got != StateClosed {
		t.Fatalf("new breaker state = %v, want StateClosed", got)
	}
}

func TestCircuitBreaker_ClosedPassesThroughSuccess(t *testing.T) {
	cb := newTestBreaker(newFakeClock())
	sc := newScriptedCall() // always succeeds
	if err := cb.Execute(context.Background(), sc.fn()); err != nil {
		t.Fatalf("Execute on closed breaker = %v, want nil", err)
	}
	if sc.count() != 1 {
		t.Fatalf("fn invoked %d times, want 1", sc.count())
	}
	if cb.State() != StateClosed {
		t.Fatalf("state after success = %v, want StateClosed", cb.State())
	}
}

func TestCircuitBreaker_TripsOpenAfterThreshold(t *testing.T) {
	cb := newTestBreaker(newFakeClock())
	failing := func(context.Context) error { return errConn }

	// FailureThreshold=3: first 3 failures return the fn error, breaker
	// then opens.
	for i := 0; i < 3; i++ {
		err := cb.Execute(context.Background(), failing)
		if !errors.Is(err, errConn) {
			t.Fatalf("failure %d: Execute = %v, want errConn", i, err)
		}
	}
	if cb.State() != StateOpen {
		t.Fatalf("state after %d failures = %v, want StateOpen", 3, cb.State())
	}
}

func TestCircuitBreaker_OpenRejectsFastWithoutCallingFn(t *testing.T) {
	cb := newTestBreaker(newFakeClock())
	for i := 0; i < 3; i++ {
		_ = cb.Execute(context.Background(), func(context.Context) error { return err500 })
	}
	if cb.State() != StateOpen {
		t.Fatalf("precondition: breaker not open (%v)", cb.State())
	}

	called := false
	err := cb.Execute(context.Background(), func(context.Context) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("open breaker Execute = %v, want ErrCircuitOpen", err)
	}
	if called {
		t.Fatal("fn was invoked while breaker open; must fail fast")
	}
}

func TestCircuitBreaker_ConsecutiveResetsOnSuccess(t *testing.T) {
	cb := newTestBreaker(newFakeClock())
	// 2 failures (below threshold), then a success must reset the counter.
	_ = cb.Execute(context.Background(), func(context.Context) error { return errConn })
	_ = cb.Execute(context.Background(), func(context.Context) error { return errConn })
	if err := cb.Execute(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("success call = %v, want nil", err)
	}
	// 2 more failures should NOT open (counter was reset).
	_ = cb.Execute(context.Background(), func(context.Context) error { return errConn })
	_ = cb.Execute(context.Background(), func(context.Context) error { return errConn })
	if cb.State() != StateClosed {
		t.Fatalf("state = %v, want StateClosed (success should reset failure count)", cb.State())
	}
}

func TestCircuitBreaker_HalfOpenAfterTimeout(t *testing.T) {
	clk := newFakeClock()
	cb := newTestBreaker(clk)
	for i := 0; i < 3; i++ {
		_ = cb.Execute(context.Background(), func(context.Context) error { return err500 })
	}
	if cb.State() != StateOpen {
		t.Fatalf("precondition: want open, got %v", cb.State())
	}

	// Before OpenTimeout elapses, still open + rejects.
	clk.Advance(4 * time.Second)
	if err := cb.Execute(context.Background(), func(context.Context) error { return nil }); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("before timeout Execute = %v, want ErrCircuitOpen", err)
	}

	// After OpenTimeout, a probe is admitted (half-open) and on success
	// the breaker closes.
	clk.Advance(2 * time.Second) // total 6s > 5s OpenTimeout
	probeCalled := false
	err := cb.Execute(context.Background(), func(context.Context) error {
		probeCalled = true
		return nil
	})
	if err != nil {
		t.Fatalf("half-open probe Execute = %v, want nil", err)
	}
	if !probeCalled {
		t.Fatal("half-open probe fn was not called")
	}
	if cb.State() != StateClosed {
		t.Fatalf("state after successful probe = %v, want StateClosed", cb.State())
	}
}

func TestCircuitBreaker_HalfOpenProbeFailureReopens(t *testing.T) {
	clk := newFakeClock()
	cb := newTestBreaker(clk)
	for i := 0; i < 3; i++ {
		_ = cb.Execute(context.Background(), func(context.Context) error { return err500 })
	}
	clk.Advance(6 * time.Second) // exceed OpenTimeout → half-open eligible

	// Probe fails → breaker must return to open, not close.
	err := cb.Execute(context.Background(), func(context.Context) error { return err500 })
	if !errors.Is(err, err500) {
		t.Fatalf("probe Execute = %v, want err500 (fn error surfaced)", err)
	}
	if cb.State() != StateOpen {
		t.Fatalf("state after failed probe = %v, want StateOpen", cb.State())
	}
}
