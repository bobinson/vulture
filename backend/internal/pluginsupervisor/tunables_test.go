package pluginsupervisor_test

// RED tests for operator-overridable tunables (MINOR #17).
// VULTURE_SUPERVISOR_* env vars override the package-level constants.

import (
	"testing"
	"time"

	"github.com/vulture/backend/internal/pluginsupervisor"
)

func TestTunables_DefaultsWhenEnvUnset(t *testing.T) {
	// All VULTURE_SUPERVISOR_* env vars unset (t.Setenv cleared by
	// previous tests). LoadTunables returns the package-level defaults.
	tn := pluginsupervisor.LoadTunables()
	if tn.ProbeIntervalS != 30 {
		t.Errorf("ProbeIntervalS default = %d; want 30", tn.ProbeIntervalS)
	}
	if tn.WarmupS != 10 {
		t.Errorf("WarmupS default = %d; want 10", tn.WarmupS)
	}
	if tn.ProbeFailureThreshold != 3 {
		t.Errorf("ProbeFailureThreshold default = %d; want 3", tn.ProbeFailureThreshold)
	}
	if tn.RestartStormWindowS != 60 {
		t.Errorf("RestartStormWindowS default = %d; want 60", tn.RestartStormWindowS)
	}
	if tn.RestartStormMax != 3 {
		t.Errorf("RestartStormMax default = %d; want 3", tn.RestartStormMax)
	}
	if tn.PullConcurrency != 4 {
		t.Errorf("PullConcurrency default = %d; want 4", tn.PullConcurrency)
	}
	if tn.StopTimeoutS != 10 {
		t.Errorf("StopTimeoutS default = %d; want 10", tn.StopTimeoutS)
	}
}

func TestTunables_EnvOverrides_MINOR17(t *testing.T) {
	t.Setenv("VULTURE_SUPERVISOR_PROBE_INTERVAL_S", "7")
	t.Setenv("VULTURE_SUPERVISOR_WARMUP_S", "3")
	t.Setenv("VULTURE_SUPERVISOR_PROBE_FAILURE_THRESHOLD", "5")
	t.Setenv("VULTURE_SUPERVISOR_RESTART_STORM_WINDOW_S", "90")
	t.Setenv("VULTURE_SUPERVISOR_RESTART_STORM_MAX", "7")
	t.Setenv("VULTURE_SUPERVISOR_PULL_CONCURRENCY", "8")
	t.Setenv("VULTURE_SUPERVISOR_STOP_TIMEOUT_S", "20")

	tn := pluginsupervisor.LoadTunables()
	if tn.ProbeIntervalS != 7 {
		t.Errorf("ProbeIntervalS override = %d; want 7", tn.ProbeIntervalS)
	}
	if tn.WarmupS != 3 {
		t.Errorf("WarmupS override = %d; want 3", tn.WarmupS)
	}
	if tn.ProbeFailureThreshold != 5 {
		t.Errorf("ProbeFailureThreshold override = %d; want 5", tn.ProbeFailureThreshold)
	}
	if tn.RestartStormWindowS != 90 {
		t.Errorf("RestartStormWindowS override = %d; want 90", tn.RestartStormWindowS)
	}
	if tn.RestartStormMax != 7 {
		t.Errorf("RestartStormMax override = %d; want 7", tn.RestartStormMax)
	}
	if tn.PullConcurrency != 8 {
		t.Errorf("PullConcurrency override = %d; want 8", tn.PullConcurrency)
	}
	if tn.StopTimeoutS != 20 {
		t.Errorf("StopTimeoutS override = %d; want 20", tn.StopTimeoutS)
	}
}

func TestTunables_InvalidEnvFallsBackToDefault(t *testing.T) {
	t.Setenv("VULTURE_SUPERVISOR_PROBE_INTERVAL_S", "not-a-number")
	t.Setenv("VULTURE_SUPERVISOR_PULL_CONCURRENCY", "")
	tn := pluginsupervisor.LoadTunables()
	if tn.ProbeIntervalS != 30 {
		t.Errorf("invalid env should fall back to default 30; got %d", tn.ProbeIntervalS)
	}
	if tn.PullConcurrency != 4 {
		t.Errorf("empty env should fall back to default 4; got %d", tn.PullConcurrency)
	}
}

func TestTunables_DurationHelper(t *testing.T) {
	// Convenience: tunables expose Duration() helpers so callers don't
	// repeatedly multiply by time.Second.
	t.Setenv("VULTURE_SUPERVISOR_PROBE_INTERVAL_S", "12")
	tn := pluginsupervisor.LoadTunables()
	if tn.ProbeInterval() != 12*time.Second {
		t.Errorf("ProbeInterval() = %v; want 12s", tn.ProbeInterval())
	}
}
