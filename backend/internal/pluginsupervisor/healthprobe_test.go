package pluginsupervisor_test

// RED tests for the HealthProber. Covers AC #5 and #6:
//   - HTTP probe against the plugin's /health endpoint.
//   - 3 consecutive failures -> Unhealthy callback.
//   - Recovery: 1 success after N failures -> Healthy callback.
//   - Per-probe timeout respected.

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vulture/backend/internal/pluginsupervisor"
)

// stateRecorder collects state transitions emitted by the prober.
type stateRecorder struct {
	mu     sync.Mutex
	states []pluginsupervisor.PluginState
}

func (r *stateRecorder) add(s pluginsupervisor.PluginState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states = append(r.states, s)
}

func (r *stateRecorder) hasState(want pluginsupervisor.PluginState) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.states {
		if s == want {
			return true
		}
	}
	return false
}

func TestHealthProbe_SuccessReturnsNoError_AC5(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	pr := pluginsupervisor.NewHealthProber(pluginsupervisor.ProbeConfig{
		Interval:         20 * time.Millisecond,
		Timeout:          50 * time.Millisecond,
		FailureThreshold: 3,
		Warmup:           0,
	})
	defer pr.StopAll()

	rec := &stateRecorder{}
	pr.Start("x", srv.URL+"/health", func(s pluginsupervisor.PluginState) {
		rec.add(s)
	})

	// Wait briefly for at least one probe.
	deadline := time.After(500 * time.Millisecond)
	for {
		if rec.hasState(pluginsupervisor.StateHealthy) {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("expected Healthy state within 500ms; got %v", rec.states)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestHealthProbe_3ConsecutiveFailuresTriggerUnhealthy_AC6(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()

	pr := pluginsupervisor.NewHealthProber(pluginsupervisor.ProbeConfig{
		Interval:         10 * time.Millisecond,
		Timeout:          50 * time.Millisecond,
		FailureThreshold: 3,
		Warmup:           0,
	})
	defer pr.StopAll()

	rec := &stateRecorder{}
	pr.Start("x", srv.URL+"/health", func(s pluginsupervisor.PluginState) {
		rec.add(s)
	})

	deadline := time.After(2 * time.Second)
	for {
		if rec.hasState(pluginsupervisor.StateUnhealthy) {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("expected Unhealthy after 3 failures; got %v", rec.states)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestHealthProbe_RecoveryAfterFailures_AC6(t *testing.T) {
	var failCount atomic.Int32
	failCount.Store(3) // first 3 calls fail, then succeed
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failCount.Add(-1) >= 0 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	pr := pluginsupervisor.NewHealthProber(pluginsupervisor.ProbeConfig{
		Interval:         10 * time.Millisecond,
		Timeout:          50 * time.Millisecond,
		FailureThreshold: 3,
		Warmup:           0,
	})
	defer pr.StopAll()

	rec := &stateRecorder{}
	pr.Start("x", srv.URL+"/health", func(s pluginsupervisor.PluginState) {
		rec.add(s)
	})

	deadline := time.After(2 * time.Second)
	for {
		if rec.hasState(pluginsupervisor.StateUnhealthy) && rec.hasState(pluginsupervisor.StateHealthy) {
			// Both transitions should be observable. Last should be Healthy.
			break
		}
		select {
		case <-deadline:
			t.Fatalf("expected Unhealthy then Healthy; got %v", rec.states)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestHealthProbe_TimeoutRespected(t *testing.T) {
	// Server that takes much longer than the timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	pr := pluginsupervisor.NewHealthProber(pluginsupervisor.ProbeConfig{
		Interval:         20 * time.Millisecond,
		Timeout:          30 * time.Millisecond,
		FailureThreshold: 3,
		Warmup:           0,
	})
	defer pr.StopAll()

	rec := &stateRecorder{}
	pr.Start("x", srv.URL+"/health", func(s pluginsupervisor.PluginState) {
		rec.add(s)
	})

	// Within ~250ms of probing, 3 consecutive timeouts should mark Unhealthy.
	deadline := time.After(1500 * time.Millisecond)
	for {
		if rec.hasState(pluginsupervisor.StateUnhealthy) {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("expected timeout to be treated as failure; got %v", rec.states)
		case <-time.After(20 * time.Millisecond):
		}
	}
}
