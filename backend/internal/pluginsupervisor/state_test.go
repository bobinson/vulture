package pluginsupervisor_test

// RED tests for the state machine and restart-storm tracker.
// Covers AC #7 (restart-storm cap), legal state transitions, and the
// sliding-window correctness of the storm tracker.

import (
	"sync"
	"testing"
	"time"

	"github.com/vulture/backend/internal/pluginsupervisor"
)

func TestStateMachine_LegalTransitions(t *testing.T) {
	sm := pluginsupervisor.NewStateMachine("x")
	// Idle -> Pulling is legal.
	if err := sm.Transition(pluginsupervisor.StatePulling); err != nil {
		t.Errorf("Idle->Pulling should be legal: %v", err)
	}
	// Pulling -> Healthy is NOT legal (must go through Starting/Probing).
	if err := sm.Transition(pluginsupervisor.StateHealthy); err == nil {
		t.Errorf("Pulling->Healthy must be illegal")
	}
}

func TestStateMachine_IdleToHealthyIllegal(t *testing.T) {
	sm := pluginsupervisor.NewStateMachine("x")
	if err := sm.Transition(pluginsupervisor.StateHealthy); err == nil {
		t.Errorf("Idle->Healthy must be illegal (must go through Pulling/Starting/Probing)")
	}
}

func TestStateMachine_HappyPath(t *testing.T) {
	sm := pluginsupervisor.NewStateMachine("x")
	chain := []pluginsupervisor.PluginState{
		pluginsupervisor.StatePulling,
		pluginsupervisor.StateStarting,
		pluginsupervisor.StateProbing,
		pluginsupervisor.StateHealthy,
	}
	for _, s := range chain {
		if err := sm.Transition(s); err != nil {
			t.Fatalf("transition to %v: %v", s, err)
		}
	}
	if sm.Current() != pluginsupervisor.StateHealthy {
		t.Errorf("final state = %v; want Healthy", sm.Current())
	}
}

func TestRestartStormTracker_ThreeEventsInWindowTriggersFailed_AC7(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	tr := pluginsupervisor.NewRestartTracker(60*time.Second, 3, clock.Now)
	if tr.Record() {
		t.Errorf("after 1 event, storm cap not yet exceeded")
	}
	clock.advance(5 * time.Second)
	if tr.Record() {
		t.Errorf("after 2 events, storm cap not yet exceeded")
	}
	clock.advance(5 * time.Second)
	if !tr.Record() {
		t.Errorf("after 3 events in 60s window, storm cap must be exceeded")
	}
}

func TestRestartStormTracker_SlidingWindow(t *testing.T) {
	// Two events at t=0,t=5; one at t=70 -> only 1 in current 60s window.
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	tr := pluginsupervisor.NewRestartTracker(60*time.Second, 3, clock.Now)
	tr.Record() // t=0
	clock.advance(5 * time.Second)
	tr.Record() // t=5
	clock.advance(65 * time.Second)
	// Window is now (10s, 70s]; only the 3rd event lands within it.
	if tr.Record() { // t=70: 1 event in window (just this one)
		t.Errorf("sliding window failed: t=0 and t=5 should have aged out")
	}
}

func TestStateMachine_ConcurrentTransitionsSafeForRace(t *testing.T) {
	// Run with -race to verify mutex correctness.
	sm := pluginsupervisor.NewStateMachine("x")
	_ = sm.Transition(pluginsupervisor.StatePulling)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sm.Transition(pluginsupervisor.StateStarting)
			_ = sm.Current()
		}()
	}
	wg.Wait()
}

// fakeClock is a t.Now()-replacement under test control.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
