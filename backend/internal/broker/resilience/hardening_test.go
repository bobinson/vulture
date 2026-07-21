package resilience

import (
	"context"
	"errors"
	"testing"
	"time"
)

type alwaysRetry struct{}

func (alwaysRetry) Retryable(error) (bool, time.Duration) { return true, 0 }

// M2 (§26): the retry token-bucket must seed to a usable burst at construction
// so a freshly-scaled stateless replica retries a transient failure on its
// FIRST call — not only after ~10 calls have accrued fractional credit.
func TestRetrier_FreshReplicaRetriesImmediately(t *testing.T) {
	attempts := 0
	r := NewRetrier(RetrierConfig{
		Policy:     RetryPolicy{MaxAttempts: 2, BaseBackoff: time.Millisecond, MaxBackoff: time.Millisecond, RetryBudgetFraction: 0.1},
		Classifier: alwaysRetry{},
		Clock:      systemClock{},
		Jitter:     func(d time.Duration) time.Duration { return 0 },
	})
	err := r.Execute(context.Background(), func(context.Context) error {
		attempts++
		if attempts < 2 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("first-call retry did not happen (empty bucket regression): %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2 (one retry on a fresh retrier)", attempts)
	}
}

// M10 (§26): a breaker built without explicit thresholds must still be able to
// recover. A zero-value HalfOpenMaxCalls used to make a tripped breaker admit
// no probes and stay open forever.
func TestCircuitBreaker_DefaultsAllowRecovery(t *testing.T) {
	b := NewCircuitBreaker(CircuitConfig{FailureThreshold: 1, OpenTimeout: time.Nanosecond})
	// Trip it.
	_ = b.Execute(context.Background(), func(context.Context) error { return errors.New("boom") })
	time.Sleep(time.Millisecond) // let OpenTimeout elapse → half-open
	// A probe must be admitted and, on success, eventually close the breaker.
	if err := b.Execute(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("half-open probe rejected — breaker wedged open with zero-value thresholds: %v", err)
	}
}

// M3 (§26): the RetrierPool hands out an isolated retrier per key so one
// provider's failure storm cannot drain a shared retry budget and starve
// another provider's retries.
func TestRetrierPool_KeysAreIsolated(t *testing.T) {
	cfg := RetrierConfig{
		Policy:     RetryPolicy{MaxAttempts: 1, BaseBackoff: time.Millisecond, MaxBackoff: time.Millisecond, RetryBudgetFraction: 0.0},
		Classifier: alwaysRetry{},
		Clock:      systemClock{},
		Jitter:     func(d time.Duration) time.Duration { return 0 },
	}
	pool := NewRetrierPool(cfg)
	if pool.For("openai") != pool.For("openai") {
		t.Fatal("pool returned different retriers for the same key")
	}
	if pool.For("openai") == pool.For("anthropic") {
		t.Fatal("pool shared one retrier across providers (budget starvation risk)")
	}
}
