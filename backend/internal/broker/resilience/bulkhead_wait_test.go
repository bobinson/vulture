package resilience

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Contract: a call that finds every slot busy WAITS for one instead of being
// refused at once. An audit starts every agent together, so a burst above the
// cap is the normal shape of the load; shedding it turned a momentary queue into
// thousands of rate_limited answers. The wait is bounded three ways: a freed
// slot admits the waiter, the call's context ending releases it, and MaxWait
// expiring sheds it with ErrBulkheadFull. Only waitersPerSlot×MaxConcurrent
// calls may wait at once; beyond that the bulkhead still sheds fast.

// holder occupies n slots of bh with calls that block until release() is called.
type holder struct {
	release func()
	done    sync.WaitGroup
}

func occupy(t *testing.T, bh Bulkhead, n int) *holder {
	t.Helper()
	gate := make(chan struct{})
	started := make(chan struct{}, n)
	h := &holder{}
	var once sync.Once
	h.release = func() { once.Do(func() { close(gate) }) }
	for i := 0; i < n; i++ {
		h.done.Add(1)
		go func() {
			defer h.done.Done()
			_ = bh.Execute(context.Background(), func(context.Context) error {
				started <- struct{}{}
				<-gate
				return nil
			})
		}()
	}
	for i := 0; i < n; i++ {
		recvStarted(t, started)
	}
	t.Cleanup(func() { h.release(); h.done.Wait() })
	return h
}

// waitForWaiters blocks until bh reports n queued calls.
func waitForWaiters(t *testing.T, bh Bulkhead, n int64) {
	t.Helper()
	b := bh.(*bulkhead)
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt64(&b.waiting) != n {
		if time.Now().After(deadline) {
			t.Fatalf("waiting = %d, want %d", atomic.LoadInt64(&b.waiting), n)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBulkhead_WaitsForAFreedSlot(t *testing.T) {
	bh := NewBulkhead(BulkheadConfig{MaxConcurrent: 1})
	h := occupy(t, bh, 1)

	var ran atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- bh.Execute(context.Background(), func(context.Context) error {
			ran.Store(true)
			return nil
		})
	}()
	waitForWaiters(t, bh, 1)
	select {
	case err := <-done:
		t.Fatalf("over-cap Execute returned %v while the slot was held; it must wait", err)
	case <-time.After(50 * time.Millisecond):
	}

	h.release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("queued Execute = %v, want nil once a slot freed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued Execute was not admitted after the slot freed")
	}
	if !ran.Load() {
		t.Fatal("admitted waiter did not run fn")
	}
	h.done.Wait()
	if got := bh.InFlight(); got != 0 {
		t.Fatalf("InFlight = %d after all calls returned, want 0", got)
	}
}

func TestBulkhead_WaiterReturnsPromptlyWhenContextEnds(t *testing.T) {
	bh := NewBulkhead(BulkheadConfig{MaxConcurrent: 1})
	h := occupy(t, bh, 1)

	ctx, cancel := context.WithCancel(context.Background())
	var ran atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- bh.Execute(ctx, func(context.Context) error { ran.Store(true); return nil })
	}()
	waitForWaiters(t, bh, 1)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled waiter = %v, want context.Canceled (the caller left; not a shed)", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a waiter whose context ended kept waiting for a slot")
	}
	if ran.Load() {
		t.Fatal("a cancelled waiter must not run fn")
	}
	waitForWaiters(t, bh, 0)

	// The abandoned wait must not leak a slot: the holder's slot still frees.
	h.release()
	h.done.Wait()
	if err := bh.Execute(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("Execute after an abandoned wait = %v, want nil", err)
	}
}

func TestBulkhead_WaiterCapShedsFast(t *testing.T) {
	const slots = 2
	bh := NewBulkhead(BulkheadConfig{MaxConcurrent: slots})
	h := occupy(t, bh, slots)

	queued := make(chan error, waitersPerSlot*slots)
	for i := 0; i < waitersPerSlot*slots; i++ {
		go func() {
			queued <- bh.Execute(context.Background(), func(context.Context) error { return nil })
		}()
	}
	waitForWaiters(t, bh, waitersPerSlot*slots)

	var ran atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- bh.Execute(context.Background(), func(context.Context) error { ran.Store(true); return nil })
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrBulkheadFull) {
			t.Fatalf("call beyond the waiter cap = %v, want ErrBulkheadFull", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a call beyond the waiter cap queued; it must be shed at once")
	}
	if ran.Load() {
		t.Fatal("a shed call must not run fn")
	}

	h.release()
	for i := 0; i < waitersPerSlot*slots; i++ {
		select {
		case err := <-queued:
			if err != nil {
				t.Fatalf("queued call = %v, want nil once slots freed", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("queued calls were not all admitted")
		}
	}
}

func TestBulkhead_MaxWaitShedsWithBulkheadFull(t *testing.T) {
	const maxWait = 50 * time.Millisecond
	bh := NewBulkhead(BulkheadConfig{MaxConcurrent: 1, MaxWait: maxWait})
	occupy(t, bh, 1)

	var ran atomic.Bool
	start := time.Now()
	err := bh.Execute(context.Background(), func(context.Context) error { ran.Store(true); return nil })
	if !errors.Is(err, ErrBulkheadFull) {
		t.Fatalf("Execute past MaxWait = %v, want ErrBulkheadFull", err)
	}
	if waited := time.Since(start); waited < maxWait {
		t.Fatalf("shed after %v, want it to wait MaxWait (%v) first", waited, maxWait)
	}
	if ran.Load() {
		t.Fatal("a call shed at MaxWait must not run fn")
	}
	waitForWaiters(t, bh, 0)
}

// The call runs on the CALLER's context, not on anything the wait derived: the
// admission bound must never shorten the call itself.
func TestBulkhead_AdmittedCallKeepsCallersContext(t *testing.T) {
	bh := NewBulkhead(BulkheadConfig{MaxConcurrent: 1, MaxWait: time.Hour})
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "caller")
	err := bh.Execute(ctx, func(c context.Context) error {
		if c.Value(key{}) != "caller" {
			return errors.New("fn did not receive the caller's context")
		}
		if _, ok := c.Deadline(); ok {
			return errors.New("the admission bound leaked into the call as a deadline")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A caller whose context has ended must never be admitted, even when a slot
// is free at that very moment: `select` picks at random among ready cases, so
// without a check after admission a done context won the slot about half the
// time — holding it, and dialing a provider, for an answer nobody reads. The
// context can end between Execute's entry check and admission, so acquire
// itself must refuse it.
func TestBulkhead_AcquireNeverAdmitsAnEndedContext(t *testing.T) {
	b := NewBulkhead(BulkheadConfig{MaxConcurrent: 1}).(*bulkhead)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	const rounds = 2000
	admitted := 0
	for i := 0; i < rounds; i++ {
		err := b.acquire(ctx) // the slot is free: both cases are ready
		if err == nil {
			admitted++
			b.release()
			continue
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("round %d: acquire = %v, want context.Canceled", i, err)
		}
	}
	if admitted != 0 {
		t.Fatalf("%d of %d acquisitions with an ended context were admitted, want 0", admitted, rounds)
	}
	if got := b.InFlight(); got != 0 {
		t.Fatalf("InFlight = %d, want 0 (a refused admission must give its slot back)", got)
	}
	if err := b.Execute(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("Execute after refused admissions = %v, want nil (no slot leaked)", err)
	}
}
