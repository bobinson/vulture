package pluginsupervisor_test

// Tests for stopped-container recovery. A plugin container that exits
// cleanly (exit 0) is not restarted by docker's `on-failure` policy, and
// the daemon-liveness loop only re-reconciles after a daemon OUTAGE. So
// when the prober reports Unhealthy while the daemon is reachable, the
// supervisor itself must notice the container is gone and relaunch it,
// bounded by the restart-storm tracker.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vulture/backend/internal/pluginsupervisor"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// recoverySup builds a supervisor whose daemon-liveness loop is
// effectively idle (1h ping interval) so only the recovery path under
// test can launch containers.
func recoverySup(t *testing.T, p pluginregistry.Plugin, dk *fakeDocker) *pluginsupervisor.Supervisor {
	t.Helper()
	sup := newDaemonSup(t, []pluginregistry.Plugin{p}, dk, time.Hour)
	if _, err := sup.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n := runCount(dk); n != 1 {
		t.Fatalf("setup: expected 1 run after Reconcile; got %d", n)
	}
	return sup
}

func runCount(dk *fakeDocker) int {
	dk.mu.Lock()
	defer dk.mu.Unlock()
	return len(dk.runs)
}

// waitRuns polls until the fake has recorded `want` docker runs.
func waitRuns(t *testing.T, dk *fakeDocker, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for runCount(dk) < want {
		if time.Now().After(deadline) {
			t.Fatalf("expected %d docker runs; got %d", want, runCount(dk))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitState polls until the plugin reaches `want`.
func waitState(t *testing.T, sup *pluginsupervisor.Supervisor, name string, want pluginsupervisor.PluginState) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for sup.Status()[name].State != want {
		if time.Now().After(deadline) {
			t.Fatalf("expected %s state %v; got %v", name, want, sup.Status()[name].State)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// assertRunsStay checks no further docker run happens within a grace
// period (negative assertion for the asynchronous recovery path).
func assertRunsStay(t *testing.T, dk *fakeDocker, want int) {
	t.Helper()
	time.Sleep(150 * time.Millisecond)
	if n := runCount(dk); n != want {
		t.Fatalf("expected docker runs to stay at %d; got %d", want, n)
	}
}

func TestRecovery_StoppedContainerRelaunched(t *testing.T) {
	p := newPlugin("semgrep", "on-failure")
	dk := &fakeDocker{} // PS reports nothing running: container stopped
	sup := recoverySup(t, p, dk)

	sup.OnHealthStateForTest("semgrep", pluginsupervisor.StateUnhealthy)

	waitRuns(t, dk, 2)
	waitState(t, sup, "semgrep", pluginsupervisor.StateProbing)
	assertRunsStay(t, dk, 2)
	if rc := sup.Status()["semgrep"].RestartCount; rc != 1 {
		t.Errorf("RestartCount = %d; want 1", rc)
	}
}

func TestRecovery_RestartPolicyNoNotRelaunched(t *testing.T) {
	p := newPlugin("semgrep", "no")
	dk := &fakeDocker{}
	sup := recoverySup(t, p, dk)

	sup.OnHealthStateForTest("semgrep", pluginsupervisor.StateUnhealthy)

	assertRunsStay(t, dk, 1)
	if st := sup.Status()["semgrep"].State; st != pluginsupervisor.StateUnhealthy {
		t.Errorf("state = %v; want Unhealthy", st)
	}
}

func TestRecovery_RunningButUnhealthyNotRelaunched(t *testing.T) {
	p := newPlugin("semgrep", "on-failure")
	dk := &fakeDocker{psResult: []pluginsupervisor.RunningContainer{
		{Name: "vulture-agent-semgrep", Image: "ghcr.io/x/semgrep:1", Status: "Up 5 minutes"},
	}}
	sup := recoverySup(t, p, dk)

	sup.OnHealthStateForTest("semgrep", pluginsupervisor.StateUnhealthy)

	assertRunsStay(t, dk, 1)
	if st := sup.Status()["semgrep"].State; st != pluginsupervisor.StateUnhealthy {
		t.Errorf("state = %v; want Unhealthy", st)
	}
}

func TestRecovery_RestartStormEndsFailed(t *testing.T) {
	t.Setenv("VULTURE_SUPERVISOR_RESTART_STORM_MAX", "3")
	p := newPlugin("semgrep", "on-failure")
	dk := &fakeDocker{}
	sup := recoverySup(t, p, dk)

	// Two stops are recovered (storm counter 1, 2) ...
	for want := 2; want <= 3; want++ {
		sup.OnHealthStateForTest("semgrep", pluginsupervisor.StateUnhealthy)
		waitRuns(t, dk, want)
		waitState(t, sup, "semgrep", pluginsupervisor.StateProbing)
	}
	// ... the third within the window trips the storm cap.
	sup.OnHealthStateForTest("semgrep", pluginsupervisor.StateUnhealthy)
	waitState(t, sup, "semgrep", pluginsupervisor.StateFailed)
	if msg := sup.Status()["semgrep"].LastError; msg == "" {
		t.Errorf("expected a restart-storm LastError; got empty")
	}
	// A further Unhealthy report must not relaunch a Failed plugin.
	sup.OnHealthStateForTest("semgrep", pluginsupervisor.StateUnhealthy)
	assertRunsStay(t, dk, 3)
	if st := sup.Status()["semgrep"].State; st != pluginsupervisor.StateFailed {
		t.Errorf("state = %v; want Failed to be sticky", st)
	}
}

func TestRecovery_DaemonDownNoRelaunch(t *testing.T) {
	p := newPlugin("semgrep", "on-failure")
	dk := &fakeDocker{}
	sup := recoverySup(t, p, dk)
	// Daemon down: every docker call that reaches the daemon fails.
	dk.mu.Lock()
	dk.infoErr = errors.New("daemon down")
	dk.psErr = errors.New("cannot connect to the docker daemon")
	dk.mu.Unlock()

	sup.OnHealthStateForTest("semgrep", pluginsupervisor.StateUnhealthy)

	assertRunsStay(t, dk, 1)
}
