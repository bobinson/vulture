package pluginsupervisor_test

// RED tests for the docker-daemon liveness goroutine (MAJOR #7 / AC #15d).
//
//   - When any plugin enters Unhealthy, the supervisor starts a single
//     daemon-liveness goroutine that pings `docker info` periodically.
//   - First successful `docker info` after failure triggers a Reconcile.
//   - When all plugins return to Healthy, the goroutine exits.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vulture/backend/internal/pluginsupervisor"
	"github.com/vulture/backend/pkg/pluginregistry"
)

func newDaemonSup(t *testing.T, plugins []pluginregistry.Plugin, dk *fakeDocker, interval time.Duration) *pluginsupervisor.Supervisor {
	t.Helper()
	reg := &fakeRegistry{enabled: plugins}
	return pluginsupervisor.NewForTest(reg, dk, &fakeProber{}, pluginsupervisor.Options{
		DockerBinary:       "docker",
		Network:            "vulture",
		AuditsDir:          "/host/audits",
		DaemonPingInterval: interval,
	})
}

func TestDaemonLiveness_StartsWhenPluginUnhealthy_MAJOR7(t *testing.T) {
	p := newPlugin("dl", "on-failure")
	dk := &fakeDocker{infoErr: errors.New("daemon down")}
	sup := newDaemonSup(t, []pluginregistry.Plugin{p}, dk, 20*time.Millisecond)

	_, _ = sup.Reconcile(context.Background())
	// Simulate prober reporting Unhealthy for the plugin.
	sup.OnHealthStateForTest("dl", pluginsupervisor.StateUnhealthy)

	deadline := time.After(1500 * time.Millisecond)
	for {
		if dk.infoCalls.Load() >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("daemon-liveness goroutine never pinged docker info; calls=%d", dk.infoCalls.Load())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestDaemonLiveness_RecoveryTriggersReconcile_AC15d(t *testing.T) {
	p := newPlugin("dlr", "on-failure")
	dk := &fakeDocker{infoErr: errors.New("daemon down")}
	sup := newDaemonSup(t, []pluginregistry.Plugin{p}, dk, 20*time.Millisecond)

	_, _ = sup.Reconcile(context.Background())
	var runsBefore atomic.Int32
	dk.mu.Lock()
	runsBefore.Store(int32(len(dk.runs)))
	dk.mu.Unlock()

	sup.OnHealthStateForTest("dlr", pluginsupervisor.StateUnhealthy)
	deadline := time.After(1 * time.Second)
	for dk.infoCalls.Load() == 0 {
		select {
		case <-deadline:
			t.Fatalf("daemon liveness loop never started")
		case <-time.After(20 * time.Millisecond):
		}
	}

	dk.mu.Lock()
	dk.infoErr = nil
	dk.mu.Unlock()

	deadline = time.After(2 * time.Second)
	for {
		dk.mu.Lock()
		n := len(dk.runs)
		dk.mu.Unlock()
		if int32(n) > runsBefore.Load() {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("daemon recovery did not trigger Reconcile")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestDaemonLiveness_ExitsWhenAllHealthy_MAJOR7(t *testing.T) {
	p := newPlugin("dlx", "on-failure")
	dk := &fakeDocker{}
	sup := newDaemonSup(t, []pluginregistry.Plugin{p}, dk, 20*time.Millisecond)

	_, _ = sup.Reconcile(context.Background())
	sup.OnHealthStateForTest("dlx", pluginsupervisor.StateUnhealthy)

	deadline := time.After(1 * time.Second)
	for dk.infoCalls.Load() == 0 {
		select {
		case <-deadline:
			t.Fatalf("liveness never started")
		case <-time.After(20 * time.Millisecond):
		}
	}

	sup.OnHealthStateForTest("dlx", pluginsupervisor.StateHealthy)
	mark := dk.infoCalls.Load()
	time.Sleep(50 * time.Millisecond)
	final := dk.infoCalls.Load()
	if final > mark+3 {
		t.Errorf("liveness goroutine did not exit after recovery (calls grew %d -> %d)", mark, final)
	}
}
