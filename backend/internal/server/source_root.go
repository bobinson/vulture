package server

import (
	"fmt"
	"log/slog"
	"time"
)

// sourceRootProbeTimeout bounds the startup check of the source root. A root
// on a mount that stopped answering (a hard-mounted network share) would
// otherwise hold up the server's start, and with it /health. Fixed, not a
// setting: the check only names the fault for the operator, since every
// request re-checks the root anyway.
const sourceRootProbeTimeout = 5 * time.Second

// logSourceRootFault names, once at startup, a configured source root the
// server cannot use (feature 0102), by its setting, so the operator need not
// infer it from refused requests. probe is the root check (CheckRoot), given
// at most wait to answer. Requests still fail closed on the root: browse,
// ingest and dispatch each re-check it.
func logSourceRootFault(probe func() error, wait time.Duration) {
	if err := probeWithin(probe, wait); err != nil {
		slog.Error("source_root_unavailable", "setting", "VULTURE_SOURCE_ROOT", "err", err)
	}
}

// probeWithin returns probe's answer, or a timeout error once wait has
// passed without one. A probe blocked on a hung mount cannot be interrupted,
// so it is abandoned rather than cancelled: its goroutine ends when the mount
// answers, and the buffered channel lets it end without a reader.
func probeWithin(probe func() error, wait time.Duration) error {
	answer := make(chan error, 1)
	go func() { answer <- probe() }()
	select {
	case err := <-answer:
		return err
	case <-time.After(wait):
		return fmt.Errorf("probe timed out after %s", wait)
	}
}
