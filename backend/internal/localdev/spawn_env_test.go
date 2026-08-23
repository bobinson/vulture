package localdev

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Feature 0073 — the spawn boundary itself.
//
// These assert against a REAL child process, because that is the only place
// the invariant is observable: AgentSpawnEnv can be perfect while the spawn
// path still calls append(os.Environ(), ...) and leaks everything. That gap is
// precisely how 0044's S5 stayed false for three months.

// childEnvDump runs a child that prints its environment, and returns it.
func childEnvDump(t *testing.T, start func(mgr *Manager, ctx context.Context) error) string {
	t.Helper()
	logDir := t.TempDir()
	mgr := NewManager()
	mgr.SetLogDir(logDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := start(mgr, ctx); err != nil {
		t.Fatalf("start error: %v", err)
	}

	logPath := filepath.Join(logDir, "envdump.log")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(logPath)
		if err == nil && strings.Contains(string(b), "ENVDUMP_DONE") {
			return string(b)
		}
		time.Sleep(25 * time.Millisecond)
	}
	b, _ := os.ReadFile(logPath)
	t.Fatalf("child never completed; log so far: %q", string(b))
	return ""
}

// StartWithEnv must hand the child EXACTLY the supplied environment.
func TestStartWithEnvGivesChildExactlyTheSuppliedEnv(t *testing.T) {
	// Seed the PARENT with the things that must not reach the child. If the
	// spawn path inherits, these show up in the dump.
	t.Setenv("VULTURE_JWT_SECRET", "leaked-jwt-sentinel")
	t.Setenv("VULTURE_DB_DSN", "postgres://leaked-dsn-sentinel")
	t.Setenv("VULTURE_WEBHOOK_SECRET", "leaked-hmac-sentinel")
	t.Setenv("LD_PRELOAD", "/tmp/leaked-preload-sentinel.so")

	full := AgentSpawnEnvFromHost(SpawnEnvPolicy{Scrub: true})
	full = append(full,
		"PATH="+os.Getenv("PATH"), // the child needs PATH to exec `printenv`
		"VULTURE_AGENT_PORT=28001",
		"VULTURE_BACKEND_URL=http://localhost:28080",
	)

	out := childEnvDump(t, func(mgr *Manager, ctx context.Context) error {
		return mgr.StartWithEnv(ctx, "envdump", "/tmp", full,
			"sh", "-c", "printenv; echo ENVDUMP_DONE")
	})

	for _, sentinel := range []string{
		"leaked-jwt-sentinel", "leaked-dsn-sentinel",
		"leaked-hmac-sentinel", "leaked-preload-sentinel",
	} {
		if strings.Contains(out, sentinel) {
			t.Errorf("child inherited %q — the spawn boundary is not enforcing the filter", sentinel)
		}
	}
	// Positive control: the supplied configuration MUST be present, or the
	// test would pass simply by spawning with an empty environment.
	for _, want := range []string{"VULTURE_AGENT_PORT=28001", "VULTURE_BACKEND_URL=http://localhost:28080"} {
		if !strings.Contains(out, want) {
			t.Errorf("child is missing supplied config %q", want)
		}
	}
}

// A nil environment must be refused: os/exec treats nil as "inherit the
// parent", which would silently restore the exact bug this feature removes.
func TestStartWithEnvRejectsNilEnv(t *testing.T) {
	mgr := NewManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.StartWithEnv(ctx, "nilenv", "/tmp", nil, "sh", "-c", "true"); err == nil {
		t.Fatal("StartWithEnv must reject a nil environment (nil means inherit-all)")
	}
	if err := mgr.StartWithEnv(ctx, "emptyenv", "/tmp", []string{}, "sh", "-c", "true"); err == nil {
		t.Fatal("StartWithEnv must reject an empty environment")
	}
}

// Start keeps inheriting — backend/frontend/npm children rely on it. This
// guards the shared start() refactor from silently changing their behaviour.
func TestStartStillInheritsParentEnv(t *testing.T) {
	t.Setenv("VULTURE_0073_INHERIT_PROBE", "inherited-ok")

	out := childEnvDump(t, func(mgr *Manager, ctx context.Context) error {
		return mgr.Start(ctx, "envdump", "/tmp", nil, "sh", "-c", "printenv; echo ENVDUMP_DONE")
	})

	if !strings.Contains(out, "inherited-ok") {
		t.Error("Start must still prepend os.Environ() for non-agent children")
	}
}
