package resilience

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Contract (§9): retrier retries ONLY on conn/429/5xx (via injected
// RetryClassifier), with jittered exponential backoff (injected Clock +
// Jitter — no real sleeps, no real randomness), honoring Retry-After, and
// under a retry budget capping the retried fraction. On budget exhaustion:
// ErrRetryBudgetExhausted. Non-retryable errors return immediately.

func newTestRetrier(clk Clock, jit Jitter, cls RetryClassifier, policy RetryPolicy) Retrier {
	return NewRetrier(RetrierConfig{
		Policy:     policy,
		Classifier: cls,
		Clock:      clk,
		Jitter:     jit,
	})
}

func basePolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:         3,
		BaseBackoff:         100 * time.Millisecond,
		MaxBackoff:          2 * time.Second,
		RetryBudgetFraction: 1.0, // effectively unlimited unless a test lowers it
	}
}

func TestRetrier_SucceedsFirstAttemptNoSleep(t *testing.T) {
	clk := newFakeClock()
	r := newTestRetrier(clk, identityJitter, defaultClassifier(), basePolicy())
	sc := newScriptedCall() // succeeds immediately
	if err := r.Execute(context.Background(), sc.fn()); err != nil {
		t.Fatalf("Execute = %v, want nil", err)
	}
	if sc.count() != 1 {
		t.Fatalf("fn calls = %d, want 1 (no retry on success)", sc.count())
	}
	if clk.pendingSleepers() != 0 {
		t.Fatalf("pending sleepers = %d, want 0 (no backoff on success)", clk.pendingSleepers())
	}
}

func TestRetrier_RetriesRetryableThenSucceeds(t *testing.T) {
	clk := newFakeClock()
	r := newTestRetrier(clk, identityJitter, defaultClassifier(), basePolicy())
	sc := newScriptedCall(errConn) // fail once, then succeed

	done := make(chan error, 1)
	go func() { done <- r.Execute(context.Background(), sc.fn()) }()

	// The retrier must schedule a backoff sleep before attempt 2.
	waitForSleeper(t, clk, 1)
	clk.Advance(basePolicy().BaseBackoff) // release the backoff

	if err := <-done; err != nil {
		t.Fatalf("Execute = %v, want nil after 1 retry", err)
	}
	if sc.count() != 2 {
		t.Fatalf("fn calls = %d, want 2", sc.count())
	}
}

func TestRetrier_DoesNotRetryNonRetryable(t *testing.T) {
	clk := newFakeClock()
	r := newTestRetrier(clk, identityJitter, defaultClassifier(), basePolicy())
	sc := newScriptedCall(errBadRequest) // 400 → not retryable

	if err := r.Execute(context.Background(), sc.fn()); !errors.Is(err, errBadRequest) {
		t.Fatalf("Execute = %v, want errBadRequest surfaced (no retry)", err)
	}
	if sc.count() != 1 {
		t.Fatalf("fn calls = %d, want 1 (must not retry a 4xx)", sc.count())
	}
	if clk.pendingSleepers() != 0 {
		t.Fatalf("pending sleepers = %d, want 0 (no backoff for non-retryable)", clk.pendingSleepers())
	}
}

func TestRetrier_ExponentialBackoffSchedule(t *testing.T) {
	clk := newFakeClock()
	// Record each backoff the retrier sleeps for by capturing via jitter.
	var mu sync.Mutex
	var seen []time.Duration
	recordJitter := func(d time.Duration) time.Duration {
		mu.Lock()
		seen = append(seen, d)
		mu.Unlock()
		return d // identity, deterministic
	}
	policy := RetryPolicy{
		MaxAttempts:         4,
		BaseBackoff:         100 * time.Millisecond,
		MaxBackoff:          10 * time.Second,
		RetryBudgetFraction: 1.0,
	}
	r := newTestRetrier(clk, recordJitter, defaultClassifier(), policy)
	sc := newScriptedCall(err500, err500, err500) // 3 failures then success on 4th

	done := make(chan error, 1)
	go func() { done <- r.Execute(context.Background(), sc.fn()) }()

	// Release 3 backoffs (attempts 2,3,4). Advance generously each time.
	for i := 0; i < 3; i++ {
		waitForSleeper(t, clk, 1)
		clk.Advance(policy.MaxBackoff)
	}
	if err := <-done; err != nil {
		t.Fatalf("Execute = %v, want nil", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 {
		t.Fatalf("backoff count = %d, want 3", len(seen))
	}
	// Exponential: 100ms, 200ms, 400ms (base * 2^(attempt-1)).
	want := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond}
	for i, w := range want {
		if seen[i] != w {
			t.Fatalf("backoff[%d] = %v, want %v (exponential from base)", i, seen[i], w)
		}
	}
}

func TestRetrier_BackoffCappedAtMax(t *testing.T) {
	clk := newFakeClock()
	var mu sync.Mutex
	var seen []time.Duration
	recordJitter := func(d time.Duration) time.Duration {
		mu.Lock()
		seen = append(seen, d)
		mu.Unlock()
		return d
	}
	policy := RetryPolicy{
		MaxAttempts:         5,
		BaseBackoff:         1 * time.Second,
		MaxBackoff:          3 * time.Second, // cap below 4th exponential step
		RetryBudgetFraction: 1.0,
	}
	r := newTestRetrier(clk, recordJitter, defaultClassifier(), policy)
	sc := newScriptedCall(err500, err500, err500, err500) // 4 failures then success

	done := make(chan error, 1)
	go func() { done <- r.Execute(context.Background(), sc.fn()) }()
	for i := 0; i < 4; i++ {
		waitForSleeper(t, clk, 1)
		clk.Advance(policy.MaxBackoff)
	}
	<-done

	mu.Lock()
	defer mu.Unlock()
	// 1s, 2s, then capped at 3s, 3s (would be 4s, 8s uncapped).
	want := []time.Duration{1 * time.Second, 2 * time.Second, 3 * time.Second, 3 * time.Second}
	if len(seen) != len(want) {
		t.Fatalf("backoff count = %d, want %d", len(seen), len(want))
	}
	for i, w := range want {
		if seen[i] != w {
			t.Fatalf("backoff[%d] = %v, want %v (capped at MaxBackoff)", i, seen[i], w)
		}
	}
}

func TestRetrier_HonorsRetryAfter(t *testing.T) {
	clk := newFakeClock()
	var mu sync.Mutex
	var seen []time.Duration
	recordJitter := func(d time.Duration) time.Duration {
		mu.Lock()
		seen = append(seen, d)
		mu.Unlock()
		return d
	}
	// defaultClassifier returns Retry-After=250ms for err429. That MUST
	// override the exponential backoff computation for that attempt.
	r := newTestRetrier(clk, recordJitter, defaultClassifier(), basePolicy())
	sc := newScriptedCall(err429) // one 429 then success

	done := make(chan error, 1)
	go func() { done <- r.Execute(context.Background(), sc.fn()) }()
	waitForSleeper(t, clk, 1)
	clk.Advance(250 * time.Millisecond)
	if err := <-done; err != nil {
		t.Fatalf("Execute = %v, want nil", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("backoff count = %d, want 1", len(seen))
	}
	if seen[0] != 250*time.Millisecond {
		t.Fatalf("Retry-After wait = %v, want 250ms (server hint must win)", seen[0])
	}
}

func TestRetrier_ExhaustsMaxAttempts(t *testing.T) {
	clk := newFakeClock()
	policy := basePolicy() // MaxAttempts=3
	r := newTestRetrier(clk, identityJitter, defaultClassifier(), policy)
	// Always fail with a retryable error.
	sc := newScriptedCall(err500, err500, err500, err500, err500)

	done := make(chan error, 1)
	go func() { done <- r.Execute(context.Background(), sc.fn()) }()
	// 2 backoffs between 3 attempts.
	for i := 0; i < 2; i++ {
		waitForSleeper(t, clk, 1)
		clk.Advance(policy.MaxBackoff)
	}
	err := <-done
	if !errors.Is(err, err500) {
		t.Fatalf("exhausted Execute = %v, want last fn error (err500) surfaced", err)
	}
	if sc.count() != policy.MaxAttempts {
		t.Fatalf("fn calls = %d, want MaxAttempts=%d", sc.count(), policy.MaxAttempts)
	}
}

func TestRetrier_BudgetCapsRetriedFraction(t *testing.T) {
	clk := newFakeClock()
	// Very low budget: no retried fraction allowed → first retryable
	// failure must NOT be retried and returns ErrRetryBudgetExhausted.
	policy := RetryPolicy{
		MaxAttempts:         5,
		BaseBackoff:         100 * time.Millisecond,
		MaxBackoff:          1 * time.Second,
		RetryBudgetFraction: 0.0, // zero budget → no retries permitted
	}
	r := newTestRetrier(clk, identityJitter, defaultClassifier(), policy)
	sc := newScriptedCall(err500) // would succeed on attempt 2 if retried

	err := r.Execute(context.Background(), sc.fn())
	if !errors.Is(err, ErrRetryBudgetExhausted) {
		t.Fatalf("Execute with zero budget = %v, want ErrRetryBudgetExhausted", err)
	}
	if sc.count() != 1 {
		t.Fatalf("fn calls = %d, want 1 (budget forbids retry)", sc.count())
	}
}

func TestRetrier_BudgetAllowsBoundedRetries(t *testing.T) {
	clk := newFakeClock()
	// Budget fraction 0.5 over a stream of calls: roughly half may retry.
	// Drive enough successful (non-retried) calls to accrue budget, then
	// confirm a retryable failure is retried once budget is available.
	policy := RetryPolicy{
		MaxAttempts:         2,
		BaseBackoff:         50 * time.Millisecond,
		MaxBackoff:          1 * time.Second,
		RetryBudgetFraction: 0.5,
	}
	r := newTestRetrier(clk, identityJitter, defaultClassifier(), policy)

	// Accrue budget with successful, non-retried calls.
	for i := 0; i < 10; i++ {
		if err := r.Execute(context.Background(), newScriptedCall().fn()); err != nil {
			t.Fatalf("warmup call %d = %v, want nil", i, err)
		}
	}

	// Now a single retryable failure should be permitted to retry once.
	sc := newScriptedCall(err500)
	done := make(chan error, 1)
	go func() { done <- r.Execute(context.Background(), sc.fn()) }()
	waitForSleeper(t, clk, 1)
	clk.Advance(policy.MaxBackoff)
	if err := <-done; err != nil {
		t.Fatalf("Execute with available budget = %v, want nil", err)
	}
	if sc.count() != 2 {
		t.Fatalf("fn calls = %d, want 2 (retry allowed within budget)", sc.count())
	}
}

// waitForSleeper spins (on the fake clock, not wall time) until at least n
// sleepers are registered, so the test releases backoff deterministically.
func waitForSleeper(t *testing.T, clk *fakeClock, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for clk.pendingSleepers() < n {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d backoff sleeper(s); retrier did not schedule backoff", n)
		}
		time.Sleep(time.Millisecond)
	}
}
