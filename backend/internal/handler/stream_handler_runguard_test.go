package handler

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 0055: only one run per audit may proceed; concurrent acquirers must
// see exactly one winner (prevents double-dispatch + persist races).
//
// 0071 moved the guard from `inFlight map[string]bool` + tryAcquireRun to the
// broadcast registry, because a late subscriber needs the run's broadcaster and
// not merely the knowledge that something is running. The invariant under test
// is unchanged; only the primitive it is asserted against has moved.
func TestStreamHandler_RunGuard_SingleWinner(t *testing.T) {
	r := newBroadcastRegistry()
	const n = 50
	var winners int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := r.Open("audit-x", 8192); ok {
				atomic.AddInt32(&winners, 1)
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("expected exactly 1 run winner, got %d", winners)
	}

	// After release + immediate eviction, a new run can acquire the same id.
	r.Release("audit-x", 0)
	if _, ok := r.Open("audit-x", 8192); !ok {
		t.Errorf("expected re-acquire after release")
	}

	// A different audit is independent.
	if _, ok := r.Open("audit-y", 8192); !ok {
		t.Errorf("different audit should acquire independently")
	}
}

// While the post-run TTL window is open the audit is still owned: the run is
// finished, but re-dispatching onto the same id would re-run every agent and
// double-fire persistence against a completed audit.
func TestStreamHandler_RunGuard_TTLWindowStillOwnsTheAudit(t *testing.T) {
	r := newBroadcastRegistry()
	if _, ok := r.Open("audit-ttl", 8192); !ok {
		t.Fatal("first Open must win")
	}
	r.Release("audit-ttl", 2*time.Second)
	if _, ok := r.Open("audit-ttl", 8192); ok {
		t.Error("Open must fail while the post-run TTL window is still open")
	}
}
