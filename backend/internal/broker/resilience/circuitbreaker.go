package resilience

import (
	"context"
	"sync"
	"time"
)

// circuitBreaker is the concrete, per-(provider,model) CircuitBreaker
// (per-replica-local, §9). State transitions: closed →(consecutive failures ≥
// FailureThreshold)→ open →(after OpenTimeout)→ half-open →(consecutive probe
// successes ≥ SuccessThreshold)→ closed, or (probe failure)→ open.
type circuitBreaker struct {
	cfg CircuitConfig

	mu           sync.Mutex
	state        CircuitState
	failures     int       // consecutive failures (closed) — trip counter
	successes    int       // consecutive successes (half-open) — recovery counter
	halfOpenUsed int       // probe calls admitted in the current half-open window
	openedAt     time.Time // when the breaker last opened
}

func newCircuitBreaker(cfg CircuitConfig) *circuitBreaker {
	// Fail-safe defaults (§26/M10): a partially-configured breaker must still
	// be able to trip AND recover. In particular a zero-value HalfOpenMaxCalls
	// would admit no probes, wedging a tripped breaker open forever.
	if cfg.Clock == nil {
		cfg.Clock = systemClock{}
	}
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 5
	}
	if cfg.HalfOpenMaxCalls <= 0 {
		cfg.HalfOpenMaxCalls = 1
	}
	if cfg.SuccessThreshold <= 0 {
		cfg.SuccessThreshold = 1
	}
	if cfg.OpenTimeout <= 0 {
		cfg.OpenTimeout = 30 * time.Second
	}
	return &circuitBreaker{cfg: cfg, state: StateClosed}
}

// systemClock is the real-time Clock used when none is injected.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// State reports the current breaker state, applying any due open→half-open
// transition first so callers observe the timeout-elapsed state.
func (b *circuitBreaker) State() CircuitState {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.maybeHalfOpen()
	return b.state
}

// admit decides, under lock, whether a call may run. It returns
// ErrCircuitOpen when the breaker is (still) open.
func (b *circuitBreaker) admit() error {
	b.maybeHalfOpen()
	if b.state == StateOpen {
		return ErrCircuitOpen
	}
	if b.state == StateHalfOpen {
		return b.admitHalfOpen()
	}
	return nil
}

func (b *circuitBreaker) admitHalfOpen() error {
	if b.halfOpenUsed >= b.cfg.HalfOpenMaxCalls {
		return ErrCircuitOpen
	}
	b.halfOpenUsed++
	return nil
}

// maybeHalfOpen promotes open→half-open once OpenTimeout has elapsed.
func (b *circuitBreaker) maybeHalfOpen() {
	if b.state != StateOpen {
		return
	}
	if b.cfg.Clock.Now().Sub(b.openedAt) < b.cfg.OpenTimeout {
		return
	}
	b.state = StateHalfOpen
	b.successes = 0
	b.halfOpenUsed = 0
}

// Execute runs fn under the breaker, failing fast with ErrCircuitOpen when
// open, otherwise recording the outcome.
func (b *circuitBreaker) Execute(ctx context.Context, fn Call) error {
	b.mu.Lock()
	if err := b.admit(); err != nil {
		b.mu.Unlock()
		return err
	}
	b.mu.Unlock()

	err := fn(ctx)

	b.mu.Lock()
	b.record(err == nil)
	b.mu.Unlock()
	return err
}

// record updates counters/state from a call outcome (under lock).
func (b *circuitBreaker) record(ok bool) {
	if b.state == StateHalfOpen {
		b.recordHalfOpen(ok)
		return
	}
	b.recordClosed(ok)
}

func (b *circuitBreaker) recordClosed(ok bool) {
	if ok {
		b.failures = 0
		return
	}
	b.failures++
	if b.failures >= b.cfg.FailureThreshold {
		b.trip()
	}
}

func (b *circuitBreaker) recordHalfOpen(ok bool) {
	if !ok {
		b.trip()
		return
	}
	b.successes++
	if b.successes >= b.cfg.SuccessThreshold {
		b.close()
	}
}

func (b *circuitBreaker) trip() {
	b.state = StateOpen
	b.openedAt = b.cfg.Clock.Now()
	b.failures = 0
	b.successes = 0
	b.halfOpenUsed = 0
}

func (b *circuitBreaker) close() {
	b.state = StateClosed
	b.failures = 0
	b.successes = 0
	b.halfOpenUsed = 0
}
