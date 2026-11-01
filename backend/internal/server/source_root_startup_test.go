package server

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/pathutil"
)

// At startup a configured source root the server cannot use is named once,
// at ERROR, by its setting (feature 0102), so the operator does not have to
// infer it from refused requests. Requests still fail closed on it. The
// check is bounded: a root on a hung mount must not hold up startup.

// startupBlockedAfter is how long the tests let a startup check run before
// they report startup as blocked. Far above the bounds the tests pass in.
const startupBlockedAfter = 2 * time.Second

func TestLogSourceRootFault(t *testing.T) {
	healthy := t.TempDir()
	missing := filepath.Join(t.TempDir(), "unmounted")
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		policy pathutil.LocalSources
		logged bool
	}{
		{"missing root", pathutil.NewLocalSources(missing, false, false), true},
		{"root is a file", pathutil.NewLocalSources(file, true, false), true},
		{"healthy root", pathutil.NewLocalSources(healthy, false, false), false},
		{"no root, local mode", pathutil.NewLocalSources("", true, false), false},
		{"read-only, missing root", pathutil.NewLocalSources(missing, false, true), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := startupLog(t, func() { logSourceRootFault(c.policy.CheckRoot, sourceRootProbeTimeout) })
			wantFaultLine(t, out, c.logged)
		})
	}
}

// TestLogSourceRootFault_HungProbe: a root on a mount that stopped answering
// (a hard-mounted network share) blocks its probe in a call nothing can
// interrupt. Startup does not wait for it: past the bound the probe is
// abandoned, and the same ERROR line names it as timed out.
func TestLogSourceRootFault_HungProbe(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	hung := func() error { <-release; return nil }
	out := startupLog(t, func() { logSourceRootFault(hung, 10*time.Millisecond) })
	wantFaultLine(t, out, true)
	if !strings.Contains(out, "probe timed out") {
		t.Errorf("a hung probe logged %q; want the cause to say the probe timed out", out)
	}
}

// startupLog runs check as startup does and returns what the standard
// logger (and so slog's default handler) wrote meanwhile. It fails the test
// when check is still running after startupBlockedAfter, as the server's
// start would be. The writer is restored before the read, so a goroutine of
// another test that logs meanwhile cannot race it.
func startupLog(t *testing.T, check func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	returned := returnsWithin(check, startupBlockedAfter)
	log.SetOutput(prev)
	if !returned {
		t.Fatalf("startup still blocked on the source-root check after %s; logged %q", startupBlockedAfter, buf.String())
	}
	return buf.String()
}

// returnsWithin reports whether fn returns within d. It is the tests' own
// guard, so it does not lean on the bound under test.
func returnsWithin(fn func(), d time.Duration) bool {
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// wantFaultLine fails unless out holds an ERROR source_root_unavailable line
// naming VULTURE_SOURCE_ROOT when logged is true, and no
// source_root_unavailable line at all when it is false.
func wantFaultLine(t *testing.T, out string, logged bool) {
	t.Helper()
	named := strings.Contains(out, "ERROR source_root_unavailable setting=VULTURE_SOURCE_ROOT ")
	if named != logged || strings.Contains(out, "source_root_unavailable") != logged {
		t.Errorf("logSourceRootFault logged %q; want an ERROR line naming VULTURE_SOURCE_ROOT: %v", out, logged)
	}
}
