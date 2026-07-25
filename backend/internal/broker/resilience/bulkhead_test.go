package resilience

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// recvStarted waits (bounded) for a "started" signal. Against an
// unimplemented stub that never runs fn, this fails fast instead of hanging
// so the RED run terminates cleanly.
func recvStarted(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bulkhead to admit and run fn")
	}
}

// Contract (§9): per-provider bulkhead = semaphore concurrency cap. When all
// slots are occupied, further Execute calls load-shed FAST with
// ErrBulkheadFull (→ rate_limited), without blocking. InFlight reflects
// current occupancy. Slots release when fn returns.

func TestBulkhead_AllowsUpToCap(t *testing.T) {
	bh := NewBulkhead(BulkheadConfig{MaxConcurrent: 2})

	release := make(chan struct{})
	started := make(chan struct{}, 2)
	var wg sync.WaitGroup

	block := func(context.Context) error {
		started <- struct{}{}
		<-release
		return nil
	}

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := bh.Execute(context.Background(), block); err != nil {
				t.Errorf("Execute within cap = %v, want nil", err)
			}
		}()
	}

	// Wait for both to occupy slots.
	recvStarted(t, started)
	recvStarted(t, started)
	if got := bh.InFlight(); got != 2 {
		t.Fatalf("InFlight = %d, want 2", got)
	}
	close(release)
	wg.Wait()

	if got := bh.InFlight(); got != 0 {
		t.Fatalf("InFlight after release = %d, want 0", got)
	}
}

func TestBulkhead_ShedsWhenFull(t *testing.T) {
	bh := NewBulkhead(BulkheadConfig{MaxConcurrent: 1})

	release := make(chan struct{})
	started := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = bh.Execute(context.Background(), func(context.Context) error {
			close(started)
			<-release
			return nil
		})
	}()

	recvStarted(t, started) // slot occupied

	// Second call must shed immediately (fast, non-blocking).
	sheddedCalledFn := false
	done := make(chan error, 1)
	go func() {
		done <- bh.Execute(context.Background(), func(context.Context) error {
			sheddedCalledFn = true
			return nil
		})
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrBulkheadFull) {
			t.Fatalf("over-cap Execute = %v, want ErrBulkheadFull", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("over-cap Execute blocked; bulkhead must load-shed fast")
	}
	if sheddedCalledFn {
		t.Fatal("shed call must NOT invoke fn")
	}

	close(release)
	wg.Wait()
}

func TestBulkhead_SlotReleasedAfterShed(t *testing.T) {
	bh := NewBulkhead(BulkheadConfig{MaxConcurrent: 1})

	// Occupy and release synchronously.
	if err := bh.Execute(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("first Execute = %v, want nil", err)
	}
	// Slot must be free again immediately after fn returns.
	ran := false
	if err := bh.Execute(context.Background(), func(context.Context) error { ran = true; return nil }); err != nil {
		t.Fatalf("second Execute = %v, want nil (slot should be free)", err)
	}
	if !ran {
		t.Fatal("fn not run on freed slot")
	}
	if bh.InFlight() != 0 {
		t.Fatalf("InFlight = %d, want 0", bh.InFlight())
	}
}

func TestBulkhead_SlotReleasedOnFnError(t *testing.T) {
	bh := NewBulkhead(BulkheadConfig{MaxConcurrent: 1})
	// fn errors → slot must still be released.
	if err := bh.Execute(context.Background(), func(context.Context) error { return errConn }); !errors.Is(err, errConn) {
		t.Fatalf("Execute = %v, want errConn surfaced", err)
	}
	if bh.InFlight() != 0 {
		t.Fatalf("InFlight after erroring fn = %d, want 0", bh.InFlight())
	}
}
