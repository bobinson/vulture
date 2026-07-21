package resilience

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A breaker pool must give each (provider,model) key its OWN breaker: one
// provider's failures must not open the circuit for another (§9 must-fix —
// the single shared breaker punished healthy providers for a sick one).
func TestBreakerPool_KeysAreIsolated(t *testing.T) {
	pool := NewBreakerPool(CircuitConfig{FailureThreshold: 1, OpenTimeout: time.Hour})
	boom := errors.New("provider exploded")

	// Trip the breaker for openai:gpt-4o.
	_ = pool.For("openai:gpt-4o").Execute(context.Background(), func(context.Context) error { return boom })
	if err := pool.For("openai:gpt-4o").Execute(context.Background(), func(context.Context) error { return nil }); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("tripped key: err = %v, want ErrCircuitOpen", err)
	}

	// A different key must still be closed.
	if err := pool.For("lmstudio:qwen3").Execute(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("independent key affected by another key's failures: %v", err)
	}
}

// The pool must return the SAME breaker for the same key (state persists).
func TestBreakerPool_SameKeySameBreaker(t *testing.T) {
	pool := NewBreakerPool(CircuitConfig{FailureThreshold: 1, OpenTimeout: time.Hour})
	if pool.For("openai:gpt-4o") != pool.For("openai:gpt-4o") {
		t.Fatal("pool returned different breaker instances for the same key")
	}
}

// A bulkhead pool must cap concurrency PER PROVIDER: one slow provider
// filling its slots must not shed load for other providers (§9 must-fix).
func TestBulkheadPool_ProvidersAreIsolated(t *testing.T) {
	pool := NewBulkheadPool(BulkheadConfig{MaxConcurrent: 1})

	block := make(chan struct{})
	started := make(chan struct{})
	go func() {
		_ = pool.For("openai").Execute(context.Background(), func(context.Context) error {
			close(started)
			<-block
			return nil
		})
	}()
	<-started
	defer close(block)

	// openai's single slot is occupied → openai sheds…
	if err := pool.For("openai").Execute(context.Background(), func(context.Context) error { return nil }); !errors.Is(err, ErrBulkheadFull) {
		t.Fatalf("occupied provider: err = %v, want ErrBulkheadFull", err)
	}
	// …but lmstudio still has capacity.
	if err := pool.For("lmstudio").Execute(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("independent provider shed by another provider's load: %v", err)
	}
}
