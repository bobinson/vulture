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

// RetrierPool hands out one retrier per key — keyed by provider so one
// provider's failure storm drains only its OWN retry budget, never starving
// another provider's retries (§26/M3).
type RetrierPool interface {
	// For returns the retrier for key, creating it on first use.
	For(key string) Retrier
}

// NewRetrierPool builds a keyed retrier pool; every retrier shares cfg.
func NewRetrierPool(cfg RetrierConfig) RetrierPool {
	return &retrierPool{cfg: cfg}
}

type retrierPool struct {
	cfg RetrierConfig
	m   sync.Map // key → Retrier
}

func (p *retrierPool) For(key string) Retrier {
	if r, ok := p.m.Load(key); ok {
		return r.(Retrier)
	}
	r, _ := p.m.LoadOrStore(key, NewRetrier(p.cfg))
	return r.(Retrier)
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
