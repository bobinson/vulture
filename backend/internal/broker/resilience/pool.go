package resilience

import "sync"

// BreakerPool hands out one circuit breaker per key — the broker keys by
// "provider:model" so one provider/model's failures never open the circuit
// for another (§9). Per-replica-local, lazily created, never evicted (the
// key space is the configured model catalog — small and bounded).
type BreakerPool interface {
	// For returns the breaker for key, creating it on first use.
	For(key string) CircuitBreaker
}

// BulkheadPool hands out one bulkhead per key — the broker keys by provider
// so one slow provider cannot shed load for the others (§9).
type BulkheadPool interface {
	// For returns the bulkhead for key, creating it on first use.
	For(key string) Bulkhead
}

// NewBreakerPool builds a keyed breaker pool; every breaker shares cfg.
func NewBreakerPool(cfg CircuitConfig) BreakerPool {
	return &breakerPool{cfg: cfg}
}

type breakerPool struct {
	cfg CircuitConfig
	m   sync.Map // key → CircuitBreaker
}

func (p *breakerPool) For(key string) CircuitBreaker {
	if b, ok := p.m.Load(key); ok {
		return b.(CircuitBreaker)
	}
	b, _ := p.m.LoadOrStore(key, NewCircuitBreaker(p.cfg))
	return b.(CircuitBreaker)
}

// NewBulkheadPool builds a keyed bulkhead pool; every bulkhead shares cfg.
func NewBulkheadPool(cfg BulkheadConfig) BulkheadPool {
	return &bulkheadPool{cfg: cfg}
}

type bulkheadPool struct {
	cfg BulkheadConfig
	m   sync.Map // key → Bulkhead
}

func (p *bulkheadPool) For(key string) Bulkhead {
	if b, ok := p.m.Load(key); ok {
		return b.(Bulkhead)
	}
	b, _ := p.m.LoadOrStore(key, NewBulkhead(p.cfg))
	return b.(Bulkhead)
}
