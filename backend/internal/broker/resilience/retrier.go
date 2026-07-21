package resilience

import (
	"context"
	"sync"
	"time"
)

// budgetMaxTokens caps the retry-budget token balance so a long run of
// successful calls cannot accrue unbounded retry credit. It bounds the burst
// of retries permitted after a quiet period while still letting the
// RetryBudgetFraction govern the steady-state retried fraction (§9).
const budgetMaxTokens = 100.0

// retrier is the concrete Retrier: conn/429/5xx-only retry (via the injected
// RetryClassifier) with jittered exponential backoff (injected Clock+Jitter,
// no real sleeps/randomness), Retry-After honoring, under a token-bucket retry
// budget capping the retried fraction.
type retrier struct {
	cfg RetrierConfig

	mu     sync.Mutex
	tokens float64 // retry budget balance
}

func newRetrier(cfg RetrierConfig) *retrier {
	// Fail-safe defaults so a wiring layer can supply only Policy+Classifier
	// and leave the deterministic-test seams nil (mirrors the breaker, §26/M10).
	if cfg.Clock == nil {
		cfg.Clock = systemClock{}
	}
	if cfg.Jitter == nil {
		cfg.Jitter = func(d time.Duration) time.Duration { return d } // identity
	}
	// §26/M2: seed the bucket to a burst PROPORTIONAL to the configured retry
	// fraction, so a freshly-constructed retrier (stateless replica, cold
	// start) can retry a transient failure immediately instead of waiting for
	// ~1/fraction calls to accrue the first whole token — while a zero fraction
	// still seeds zero (RetryBudgetFraction=0 strictly means "no retries").
	seed := cfg.Policy.RetryBudgetFraction * budgetMaxTokens
	if seed > budgetMaxTokens {
		seed = budgetMaxTokens
	}
	return &retrier{cfg: cfg, tokens: seed}
}

// Execute runs fn with retries per the policy and budget.
func (r *retrier) Execute(ctx context.Context, fn Call) error {
	var lastErr error
	for attempt := 1; attempt <= r.cfg.Policy.MaxAttempts; attempt++ {
		r.credit() // each attempt accrues budget toward the retried fraction
		lastErr = fn(ctx)
		if lastErr == nil {
			return nil
		}
		wait, retryable := r.plan(lastErr, attempt)
		if !retryable {
			return lastErr
		}
		if !r.spend() {
			return ErrRetryBudgetExhausted
		}
		if err := r.cfg.Clock.Sleep(ctx, wait); err != nil {
			return err
		}
	}
	return lastErr
}

// plan reports the backoff to wait and whether a retry is warranted: the error
// must be classifier-retryable AND another attempt must remain.
func (r *retrier) plan(err error, attempt int) (time.Duration, bool) {
	if attempt >= r.cfg.Policy.MaxAttempts {
		return 0, false
	}
	retry, retryAfter := r.cfg.Classifier.Retryable(err)
	if !retry {
		return 0, false
	}
	return r.backoff(attempt, retryAfter), true
}

// backoff computes the wait for the given attempt: a server Retry-After hint
// wins outright, otherwise exponential-from-base capped at MaxBackoff, then
// passed through the injected Jitter.
func (r *retrier) backoff(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return r.cfg.Jitter(retryAfter)
	}
	d := r.cfg.Policy.BaseBackoff << (attempt - 1)
	if d > r.cfg.Policy.MaxBackoff || d <= 0 {
		d = r.cfg.Policy.MaxBackoff
	}
	return r.cfg.Jitter(d)
}

// credit adds one call's worth of budget, capped at budgetMaxTokens.
func (r *retrier) credit() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens += r.cfg.Policy.RetryBudgetFraction
	if r.tokens > budgetMaxTokens {
		r.tokens = budgetMaxTokens
	}
}

// spend consumes one retry token if available.
func (r *retrier) spend() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tokens < 1.0 {
		return false
	}
	r.tokens--
	return true
}
