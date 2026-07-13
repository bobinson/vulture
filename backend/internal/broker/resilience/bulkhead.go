package resilience

import (
	"context"
	"sync/atomic"
)

// bulkhead is the concrete, per-provider Bulkhead (§9): a buffered-channel
// semaphore capping concurrency. Over-cap Execute calls load-shed fast with
// ErrBulkheadFull rather than blocking. All hot-path ops are O(1).
type bulkhead struct {
	slots    chan struct{}
	inFlight int64
}

func newBulkhead(cfg BulkheadConfig) *bulkhead {
	return &bulkhead{slots: make(chan struct{}, cfg.MaxConcurrent)}
}

// InFlight reports current occupancy.
func (b *bulkhead) InFlight() int {
	return int(atomic.LoadInt64(&b.inFlight))
}

// Execute runs fn if a slot is free, else sheds fast with ErrBulkheadFull.
// The slot is always released when fn returns (success or error).
func (b *bulkhead) Execute(ctx context.Context, fn Call) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !b.acquire() {
		return ErrBulkheadFull
	}
	defer b.release()
	return fn(ctx)
}

func (b *bulkhead) acquire() bool {
	select {
	case b.slots <- struct{}{}:
		atomic.AddInt64(&b.inFlight, 1)
		return true
	default:
		return false
	}
}

func (b *bulkhead) release() {
	atomic.AddInt64(&b.inFlight, -1)
	<-b.slots
}
