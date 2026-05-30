package pluginsupervisor

import (
	"log"
	"os"
	"strconv"
	"time"
)

// Default tunable values. Operator overrides via VULTURE_SUPERVISOR_*
// env vars (MINOR #17). Each field has a Duration() helper so callers
// don't sprinkle `time.Duration(x) * time.Second` everywhere.
const (
	defaultProbeIntervalS        = 30
	defaultWarmupS               = 10
	defaultProbeFailureThreshold = 3
	defaultRestartStormWindowS   = 60
	defaultRestartStormMax       = 3
	defaultPullConcurrency       = 4
	defaultStopTimeoutS          = 10
)

// Tunables snapshots the operator-configurable supervisor knobs.
// Construct via LoadTunables() — callers should not zero-initialise.
type Tunables struct {
	ProbeIntervalS        int
	WarmupS               int
	ProbeFailureThreshold int
	RestartStormWindowS   int
	RestartStormMax       int
	PullConcurrency       int
	StopTimeoutS          int
}

// ProbeInterval returns the polling interval as a time.Duration.
func (t Tunables) ProbeInterval() time.Duration {
	return time.Duration(t.ProbeIntervalS) * time.Second
}

// Warmup returns the warm-up delay before the first health probe.
func (t Tunables) Warmup() time.Duration {
	return time.Duration(t.WarmupS) * time.Second
}

// RestartStormWindow returns the sliding-window length for storm detection.
func (t Tunables) RestartStormWindow() time.Duration {
	return time.Duration(t.RestartStormWindowS) * time.Second
}

// StopTimeout returns the docker stop --time value.
func (t Tunables) StopTimeout() time.Duration {
	return time.Duration(t.StopTimeoutS) * time.Second
}

// LoadTunables reads VULTURE_SUPERVISOR_* env vars and returns the
// resulting Tunables. Invalid values fall back to defaults with a
// warning to the standard logger.
func LoadTunables() Tunables {
	return Tunables{
		ProbeIntervalS:        envInt("VULTURE_SUPERVISOR_PROBE_INTERVAL_S", defaultProbeIntervalS),
		WarmupS:               envInt("VULTURE_SUPERVISOR_WARMUP_S", defaultWarmupS),
		ProbeFailureThreshold: envInt("VULTURE_SUPERVISOR_PROBE_FAILURE_THRESHOLD", defaultProbeFailureThreshold),
		RestartStormWindowS:   envInt("VULTURE_SUPERVISOR_RESTART_STORM_WINDOW_S", defaultRestartStormWindowS),
		RestartStormMax:       envInt("VULTURE_SUPERVISOR_RESTART_STORM_MAX", defaultRestartStormMax),
		PullConcurrency:       envInt("VULTURE_SUPERVISOR_PULL_CONCURRENCY", defaultPullConcurrency),
		StopTimeoutS:          envInt("VULTURE_SUPERVISOR_STOP_TIMEOUT_S", defaultStopTimeoutS),
	}
}

func envInt(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		log.Printf("[supervisor] %s=%q invalid; using default %d", name, raw, fallback)
		return fallback
	}
	return v
}
