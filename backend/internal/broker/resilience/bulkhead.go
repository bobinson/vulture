package resilience

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

// waitersPerSlot caps the admission queue at this many waiting calls per slot.
// A queue that deep already holds several full rounds of provider calls, so a
// call beyond it would wait longer than any caller allows; it is refused at once
// (ErrBulkheadFull) rather than piling up goroutines and open connections.
const waitersPerSlot = 4

// bulkhead is the concrete, per-provider Bulkhead (§9): a buffered-channel
// semaphore capping concurrency, with a bounded admission queue in front of it.
//
// A call that finds every slot busy WAITS for one. An audit starts all of its
// agents together, so demand above the cap is the normal shape of the load, not
// an overload: refusing it outright turned a momentary queue into thousands of
// rate_limited answers, which the callers' own retries then multiplied. The wait
// ends when a slot frees, when the call's context ends, or when MaxWait elapses
// (shed as ErrBulkheadFull); and at most waitersPerSlot×MaxConcurrent calls wait
// at once — past that the bulkhead still sheds fast. Waiters are admitted in
// arrival order: the runtime queues blocked senders on the slot channel FIFO and
// hands a freed slot to the head of that queue. Hot-path ops are O(1).
type bulkhead struct {
	slots      chan struct{}
	inFlight   int64
	waiting    int64
	maxWaiting int64
	maxWait    time.Duration
}

func newBulkhead(cfg BulkheadConfig) *bulkhead {
	return &bulkhead{
		slots:      make(chan struct{}, cfg.MaxConcurrent),
		maxWaiting: int64(waitersPerSlot * cfg.MaxConcurrent),
		maxWait:    cfg.MaxWait,
	}
}

// InFlight reports current occupancy.
func (b *bulkhead) InFlight() int {
	return int(atomic.LoadInt64(&b.inFlight))
}

// Execute runs fn once a slot is free, waiting for one (bounded) when none is.
// fn receives the caller's ctx unchanged: the admission bound limits only the
// wait, never the call. The slot is always released when fn returns.
func (b *bulkhead) Execute(ctx context.Context, fn Call) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.acquire(ctx); err != nil {
		return err
	}
	defer b.release()
	return fn(ctx)
}

// acquire takes a slot and gives it straight back if the caller has left by
// then. `select` picks at random among ready cases, so a waiter whose context
// ended just as a slot freed can be handed the slot; and a context can end
// between Execute's entry check and the fast path. Either way an admitted
// call for a caller that is gone would hold a slot and dial a provider for an
// answer nobody reads.
func (b *bulkhead) acquire(ctx context.Context) error {
	if err := b.take(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		b.release()
		return err
	}
	return nil
}

// take claims a free slot at once, else joins the admission queue — or sheds
// when the queue is already full.
func (b *bulkhead) take(ctx context.Context) error {
	select {
	case b.slots <- struct{}{}:
		b.admitted()
		return nil
	default:
	}
	if atomic.AddInt64(&b.waiting, 1) > b.maxWaiting {
		atomic.AddInt64(&b.waiting, -1)
		return ErrBulkheadFull
	}
	defer atomic.AddInt64(&b.waiting, -1)
	return b.wait(ctx)
}

// wait blocks for a slot until ctx ends or MaxWait elapses. A caller that leaves
// gets its own context error back (it was not refused, it left); an expired
// wait is a shed.
func (b *bulkhead) wait(ctx context.Context) error {
	expired, stop := b.waitTimer()
	defer stop()
	select {
	case b.slots <- struct{}{}:
		b.admitted()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-expired:
		return fmt.Errorf("%w: no slot within %s", ErrBulkheadFull, b.maxWait)
	}
}

// waitTimer arms MaxWait; with none configured the wait is bounded by the
// caller's context alone (a nil channel never fires).
func (b *bulkhead) waitTimer() (<-chan time.Time, func()) {
	if b.maxWait <= 0 {
		return nil, func() {}
	}
	t := time.NewTimer(b.maxWait)
	return t.C, func() { t.Stop() }
}

func (b *bulkhead) admitted() {
	atomic.AddInt64(&b.inFlight, 1)
}

func (b *bulkhead) release() {
	atomic.AddInt64(&b.inFlight, -1)
	<-b.slots
}
