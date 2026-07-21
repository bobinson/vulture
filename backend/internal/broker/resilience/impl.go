// This file declares the resilience constructors + deterministic-test seams
// (injected clock, jitter, retry classifier). The constructors return the
// interface types so call sites depend only on the seam, not the concrete
// implementation.
package resilience

import (
	"context"
	"time"
)

// Clock is the injectable time seam so tests use a fake clock (no real
// sleeps). Now reports current time; Sleep blocks for d or until ctx is
// done, returning ctx.Err() on cancellation.
type Clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

// Jitter maps a backoff duration to a jittered duration. Injected so tests
// pin randomness (e.g. identity, or full-jitter with a seeded source).
type Jitter func(d time.Duration) time.Duration

// RetryClassifier decides whether a Call error is retryable (conn/429/5xx
// ONLY per §9) and extracts a server-provided Retry-After hint (0 if none).
// Non-retryable errors (4xx other than 429, auth, invalid_request) return
// retry=false.
type RetryClassifier interface {
	Retryable(err error) (retry bool, retryAfter time.Duration)
}

// CircuitConfig configures a per-(provider,model) breaker.
type CircuitConfig struct {
	// FailureThreshold is the consecutive-failure count that trips closed→open.
	FailureThreshold int
	// OpenTimeout is how long the breaker stays open before allowing a
	// half-open probe.
	OpenTimeout time.Duration
	// HalfOpenMaxCalls is the number of probe calls allowed in half-open.
	HalfOpenMaxCalls int
	// SuccessThreshold is the consecutive half-open successes to close.
	SuccessThreshold int
	Clock            Clock
	// IsFailure classifies a non-nil Call error as a provider-HEALTH failure
	// (§32.1 #1). Only errors it returns true for count toward tripping; other
	// non-nil errors (permanent client faults, ctx cancellation, usage-missing)
	// are NEUTRAL — they neither trip nor reset the counter, so a request-shape
	// bug or a self-imposed deadline cannot open a shared (provider,model)
	// breaker. When nil, the legacy behavior holds: ANY non-nil error counts.
	IsFailure func(error) bool
}

// BulkheadConfig configures a per-provider bulkhead.
type BulkheadConfig struct {
	// MaxConcurrent is the semaphore size (concurrency cap).
	MaxConcurrent int
}

// RetrierConfig configures a retry-budget retrier.
type RetrierConfig struct {
	Policy     RetryPolicy
	Classifier RetryClassifier
	Clock      Clock
	Jitter     Jitter
}

// NewCircuitBreaker builds a per-(provider,model) breaker (per-replica-local).
func NewCircuitBreaker(cfg CircuitConfig) CircuitBreaker { return newCircuitBreaker(cfg) }

// NewBulkhead builds a per-provider bulkhead (semaphore concurrency cap).
func NewBulkhead(cfg BulkheadConfig) Bulkhead { return newBulkhead(cfg) }

// NewRetrier builds a retry-budget retrier.
func NewRetrier(cfg RetrierConfig) Retrier { return newRetrier(cfg) }
