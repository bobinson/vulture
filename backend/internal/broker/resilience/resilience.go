// Package resilience defines the LLM-broker chaos-resilience wrappers
// (feature 0064, §9): a per-(provider,model) circuit breaker
// (per-replica-local for P0), a per-provider bulkhead (pool + concurrency
// cap), and a retry budget capping the retried fraction. Wrappers compose
// around a provider egress call.
//
// This file is an interface STUB: types/interfaces are fully defined;
// method bodies return ErrNotImplemented.
package resilience

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented is returned by every stub method until the real
// implementation lands.
var ErrNotImplemented = errors.New("broker/resilience: not implemented")

// Sentinel resilience errors (map onto §5 API error codes).
var (
	// ErrCircuitOpen indicates the breaker for a (provider,model) is
	// open; the caller should fail over (§9).
	ErrCircuitOpen = errors.New("broker/resilience: circuit open")
	// ErrBulkheadFull indicates the per-provider concurrency cap is
	// reached; load-shed fast → rate_limited (§9).
	ErrBulkheadFull = errors.New("broker/resilience: bulkhead full")
	// ErrRetryBudgetExhausted indicates the retried-fraction cap was hit.
	ErrRetryBudgetExhausted = errors.New("broker/resilience: retry budget exhausted")
)

// CircuitState is the breaker state for a (provider,model).
type CircuitState int

const (
	// StateClosed means calls flow normally.
	StateClosed CircuitState = iota
	// StateOpen means calls are rejected (fail fast).
	StateOpen
	// StateHalfOpen means a probe call is allowed to test recovery.
	StateHalfOpen
)

// Call is the unit of work the wrappers protect: a single provider egress
// attempt. It returns its own error; wrappers decide retry/trip/shed.
type Call func(ctx context.Context) error

// CircuitBreaker guards a single (provider,model) key (§9, per-replica for
// P0, L2). Account-level breakers for 401/billing are separate instances.
type CircuitBreaker interface {
	// Execute runs fn under the breaker, returning ErrCircuitOpen when
	// open, otherwise fn's result (and recording success/failure).
	Execute(ctx context.Context, fn Call) error
	// State reports the current breaker state.
	State() CircuitState
}

// Bulkhead caps concurrency per provider (§9), isolating one slow provider
// from starving others.
type Bulkhead interface {
	// Execute runs fn if a slot is available, else ErrBulkheadFull.
	Execute(ctx context.Context, fn Call) error
	// InFlight reports current occupancy.
	InFlight() int
}

// RetryPolicy captures conn/429/5xx-only retry with backoff+jitter,
// Retry-After honoring, and a retry budget (§9).
type RetryPolicy struct {
	MaxAttempts int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	// RetryBudgetFraction caps the fraction of calls that may be retried.
	RetryBudgetFraction float64
}

// Retrier retries a Call per a RetryPolicy under a shared retry budget.
type Retrier interface {
	// Execute runs fn with retries; returns ErrRetryBudgetExhausted when
	// the budget is spent, else fn's terminal result.
	Execute(ctx context.Context, fn Call) error
}

// --- Stub implementations (module agents replace these) ---

// StubCircuitBreaker is a no-op CircuitBreaker (always closed).
type StubCircuitBreaker struct{}

// Execute always returns ErrNotImplemented.
func (StubCircuitBreaker) Execute(context.Context, Call) error { return ErrNotImplemented }

// State always reports closed.
func (StubCircuitBreaker) State() CircuitState { return StateClosed }

// StubBulkhead is a no-op Bulkhead.
type StubBulkhead struct{}

// Execute always returns ErrNotImplemented.
func (StubBulkhead) Execute(context.Context, Call) error { return ErrNotImplemented }

// InFlight always reports 0.
func (StubBulkhead) InFlight() int { return 0 }

// StubRetrier is a no-op Retrier.
type StubRetrier struct{}

// Execute always returns ErrNotImplemented.
func (StubRetrier) Execute(context.Context, Call) error { return ErrNotImplemented }

// Compile-time interface assertions.
var (
	_ CircuitBreaker = StubCircuitBreaker{}
	_ Bulkhead       = StubBulkhead{}
	_ Retrier        = StubRetrier{}
)
