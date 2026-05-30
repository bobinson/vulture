package pluginsupervisor

import (
	"fmt"
	"sync"
	"time"
)

// PluginState is one node in the supervisor's per-plugin state machine.
type PluginState int

const (
	StateIdle PluginState = iota
	StatePulling
	StateStarting
	StateProbing
	StateHealthy
	StateUnhealthy
	StateFailed
	StateRestarting
	StateStopping
)

// stateNames is the single source of truth for state.String(); a
// table-lookup keeps complexity below the gocyclo threshold (one
// switch with 9+ cases is hostile both to humans and to the linter).
var stateNames = map[PluginState]string{
	StateIdle:       "Idle",
	StatePulling:    "Pulling",
	StateStarting:   "Starting",
	StateProbing:    "Probing",
	StateHealthy:    "Healthy",
	StateUnhealthy:  "Unhealthy",
	StateFailed:     "Failed",
	StateRestarting: "Restarting",
	StateStopping:   "Stopping",
}

func (s PluginState) String() string {
	if name, ok := stateNames[s]; ok {
		return name
	}
	return "Unknown"
}

// PluginStatus is the externally observable per-plugin snapshot.
type PluginStatus struct {
	Name         string
	State        PluginState
	LastError    string
	RestartCount int
	UpdatedAt    time.Time
}

// legalTransitions defines the directed edges in the state machine.
// Any edge not listed here is rejected by StateMachine.Transition.
var legalTransitions = map[PluginState]map[PluginState]bool{
	StateIdle:       {StatePulling: true, StateStopping: true, StateFailed: true},
	StatePulling:    {StateStarting: true, StateFailed: true, StateStopping: true},
	StateStarting:   {StateProbing: true, StateFailed: true, StateStopping: true},
	StateProbing:    {StateHealthy: true, StateUnhealthy: true, StateFailed: true, StateStopping: true},
	StateHealthy:    {StateUnhealthy: true, StateStopping: true, StateRestarting: true},
	StateUnhealthy:  {StateHealthy: true, StateRestarting: true, StateFailed: true, StateStopping: true},
	StateRestarting: {StatePulling: true, StateStarting: true, StateProbing: true, StateFailed: true, StateStopping: true},
	StateFailed:     {StatePulling: true, StateStopping: true, StateRestarting: true},
	StateStopping:   {StateIdle: true},
}

// StateMachine is the per-plugin state holder. Safe for concurrent
// use by the supervisor + prober goroutines.
type StateMachine struct {
	name string
	mu   sync.Mutex
	cur  PluginState
}

// NewStateMachine constructs a machine in StateIdle.
func NewStateMachine(name string) *StateMachine {
	return &StateMachine{name: name, cur: StateIdle}
}

// Current returns the current state.
func (s *StateMachine) Current() PluginState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// Transition moves to `to`. Returns an error if the edge from the
// current state to `to` is not listed in legalTransitions.
func (s *StateMachine) Transition(to PluginState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	from := s.cur
	if from == to {
		return nil
	}
	if !legalTransitions[from][to] {
		return fmt.Errorf("illegal transition %s -> %s for plugin %s", from, to, s.name)
	}
	s.cur = to
	return nil
}

// Force sets the state regardless of legality. Used by tests and the
// supervisor when the manifest's restart policy forces a state from
// the outside (e.g. mark Failed on pull error from Idle).
func (s *StateMachine) Force(to PluginState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur = to
}

// RestartTracker implements the sliding-window restart-storm counter
// (AC #7). Window length and cap are configured at construction; the
// clock function is injected so tests can move time deterministically.
type RestartTracker struct {
	mu     sync.Mutex
	window time.Duration
	cap    int
	now    func() time.Time
	events []time.Time
}

// NewRestartTracker constructs a tracker with the given sliding-window
// length and event cap, using `now` for the current time. Production
// code passes time.Now; tests inject a controllable clock.
func NewRestartTracker(window time.Duration, capN int, now func() time.Time) *RestartTracker {
	if now == nil {
		now = time.Now
	}
	return &RestartTracker{window: window, cap: capN, now: now}
}

// Record logs a restart event at the current time and returns true if
// the storm cap is now exceeded (i.e. caller should mark Failed).
func (t *RestartTracker) Record() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	cur := t.now()
	t.events = append(t.events, cur)
	cutoff := cur.Add(-t.window)
	// Drop events older than the window.
	kept := t.events[:0]
	for _, ev := range t.events {
		if ev.After(cutoff) {
			kept = append(kept, ev)
		}
	}
	t.events = kept
	return len(t.events) >= t.cap
}

// stateStore is the supervisor's mutex-guarded map of name -> status.
type stateStore struct {
	mu   sync.Mutex
	data map[string]*statusEntry
}

type statusEntry struct {
	sm           *StateMachine
	tracker      *RestartTracker
	restartCount int
	lastError    string
	updatedAt    time.Time
}

func newStateStore() *stateStore {
	return &stateStore{data: map[string]*statusEntry{}}
}

func (s *stateStore) ensure(name string, window time.Duration, capN int, now func() time.Time) *statusEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[name]
	if !ok {
		e = &statusEntry{
			sm:        NewStateMachine(name),
			tracker:   NewRestartTracker(window, capN, now),
			updatedAt: now(),
		}
		s.data[name] = e
	}
	return e
}

func (s *stateStore) get(name string) (*statusEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[name]
	return e, ok
}

func (s *stateStore) snapshot() map[string]PluginStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]PluginStatus, len(s.data))
	for name, e := range s.data {
		out[name] = PluginStatus{
			Name:         name,
			State:        e.sm.Current(),
			LastError:    e.lastError,
			RestartCount: e.restartCount,
			UpdatedAt:    e.updatedAt,
		}
	}
	return out
}

func (s *stateStore) setError(name, msg string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.data[name]; ok {
		e.lastError = msg
		e.updatedAt = now
	}
}

// allHealthy reports whether every tracked plugin is in StateHealthy.
// Used by the daemon-liveness goroutine to decide when to exit.
func (s *stateStore) allHealthy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data) == 0 {
		return true
	}
	for _, e := range s.data {
		if e.sm.Current() != StateHealthy {
			return false
		}
	}
	return true
}
