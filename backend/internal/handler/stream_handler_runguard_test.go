package handler

import (
	"sync"
	"sync/atomic"
	"testing"
)

// 0055: only one run per audit may proceed; concurrent acquirers must
// see exactly one winner (prevents double-dispatch + persist races).
func TestStreamHandler_RunGuard_SingleWinner(t *testing.T) {
	h := &StreamHandler{inFlight: map[string]bool{}}
	const n = 50
	var winners int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h.tryAcquireRun("audit-x") {
				atomic.AddInt32(&winners, 1)
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("expected exactly 1 run winner, got %d", winners)
	}
	// After release, a new run can acquire.
	h.releaseRun("audit-x")
	if !h.tryAcquireRun("audit-x") {
		t.Errorf("expected re-acquire after release")
	}
	// A different audit is independent.
	if !h.tryAcquireRun("audit-y") {
		t.Errorf("different audit should acquire independently")
	}
}
