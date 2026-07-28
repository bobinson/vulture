package localdev

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Feature 0069 P1 — spawn verification.
//
// These tests encode the business contract that a *reported* start is a
// *verified* start. The defect they pin down: `vulture start` logged
// "started backend on port 28080" while the child had already died with
// `listen: address already in use`, leaving a zombie and a launcher that
// believed it was serving. Liveness of a port is not proof that we own it,
// and a successful fork is not proof that the child came up.

// listenOn occupies a port for the duration of the test and returns it.
func listenOn(t *testing.T) (port string, close func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	return p, func() { _ = ln.Close() }
}

// freePort returns a port that is currently unbound.
func freePort(t *testing.T) string {
	t.Helper()
	p, release := listenOn(t)
	release()
	return p
}

func TestEnsurePortFreeDetectsOccupiedPort(t *testing.T) {
	port, release := listenOn(t)
	defer release()

	err := ensurePortFree(port)
	if err == nil {
		t.Fatal("expected an error for an occupied port, got nil")
	}
	if !strings.Contains(err.Error(), port) {
		t.Errorf("error must name the port %q so the operator can find the occupant; got: %v", port, err)
	}
}

func TestEnsurePortFreeAllowsFreePort(t *testing.T) {
	if err := ensurePortFree(freePort(t)); err != nil {
		t.Fatalf("expected nil for a free port, got %v", err)
	}
}

// A child that exits immediately must be reported as a failure, and its
// stderr must reach the operator. This is the exact shape of the observed
// incident: the fork succeeded, the child died, the launcher said "started".
func TestWaitReadyFailsWhenChildExitsAndSurfacesStderr(t *testing.T) {
	mgr := NewManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const marker = "listen tcp :28080: bind: address already in use"
	err := mgr.Start(ctx, "doomed", "/tmp", nil,
		"sh", "-c", "echo '"+marker+"' >&2; exit 1")
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Probe that never succeeds — readiness must lose to the child's exit.
	err = mgr.WaitReady("doomed", func() bool { return false }, 5*time.Second)
	if err == nil {
		t.Fatal("expected an error when the child exits before becoming ready")
	}
	if !strings.Contains(err.Error(), marker) {
		t.Errorf("child stderr must be surfaced in the error; got: %v", err)
	}
}

func TestWaitReadySucceedsWhenProbePasses(t *testing.T) {
	mgr := NewManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx, "sleeper", "/tmp", nil, "sh", "-c", "sleep 10"); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer func() { mgr.StopAll(); mgr.WaitAll() }()

	calls := 0
	probe := func() bool { calls++; return calls >= 2 }
	if err := mgr.WaitReady("sleeper", probe, 5*time.Second); err != nil {
		t.Fatalf("expected readiness, got %v", err)
	}
}

func TestWaitReadyTimesOutWhileChildStillRunning(t *testing.T) {
	mgr := NewManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx, "never-ready", "/tmp", nil, "sh", "-c", "sleep 10"); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer func() { mgr.StopAll(); mgr.WaitAll() }()

	err := mgr.WaitReady("never-ready", func() bool { return false }, 300*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !strings.Contains(err.Error(), "never-ready") {
		t.Errorf("timeout error must name the process; got: %v", err)
	}
}

// Status must not report a dead child as Running. Previously Status() keyed
// off Cmd.ProcessState, which stays nil until Wait() is called — so an
// exited-but-unreaped child (a zombie) read as Running: true.
func TestStatusReportsExitedChildAsNotRunning(t *testing.T) {
	mgr := NewManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx, "quick", "/tmp", nil, "sh", "-c", "exit 3"); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st := mgr.Status()
		if len(st) == 1 && !st[0].Running {
			if st[0].ExitCode != 3 {
				t.Errorf("expected exit code 3, got %d", st[0].ExitCode)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("Status() still reports an exited child as Running")
}

// Child output must be durable. `vulture logs` could never work because
// output went only to the parent's stdout, which is discarded on the
// detached (setsid) start path.
func TestChildOutputIsWrittenToLogDir(t *testing.T) {
	logDir := t.TempDir()
	mgr := NewManager()
	mgr.SetLogDir(logDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx, "chatty", "/tmp", nil,
		"sh", "-c", "echo to-stdout; echo to-stderr >&2"); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	logPath := filepath.Join(logDir, "chatty.log")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(logPath)
		if err == nil && strings.Contains(string(b), "to-stdout") && strings.Contains(string(b), "to-stderr") {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	b, _ := os.ReadFile(logPath)
	t.Fatalf("expected both streams in %s; got %q", logPath, string(b))
}

// StopAll must actually stop. Signalling only the direct child leaves
// grandchildren alive holding the output pipes — so `vulture stop` returned
// while agents kept running and kept their ports, which is precisely how a
// stale agent survives to be adopted by a later `vulture start`.
func TestStopAllTerminatesProcessTree(t *testing.T) {
	mgr := NewManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// `sh -c` with a trailing command forks rather than execs on some shells,
	// so the sleep becomes a grandchild that survives a child-only kill.
	if err := mgr.Start(ctx, "tree", "/tmp", nil, "sh", "-c", "sleep 30 & wait"); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	start := time.Now()
	mgr.StopAll()
	mgr.WaitAll()
	if d := time.Since(start); d > 6*time.Second {
		t.Fatalf("StopAll+WaitAll took %s for a `sleep 30` grandchild — the process tree is not being terminated", d)
	}
}

// The identity check: something answering /health is not proof that *our*
// binary is answering. httpHealthProbe must only pass on a real 2xx.
func TestHTTPHealthProbe(t *testing.T) {
	okSrv := httpTestServer(t, http.StatusOK)
	defer okSrv.close()
	if !httpHealthProbe(okSrv.url + "/health")() {
		t.Error("expected probe to pass on 200")
	}

	badSrv := httpTestServer(t, http.StatusInternalServerError)
	defer badSrv.close()
	if httpHealthProbe(badSrv.url + "/health")() {
		t.Error("expected probe to fail on 500")
	}

	if httpHealthProbe("http://127.0.0.1:" + freePort(t) + "/health")() {
		t.Error("expected probe to fail when nothing is listening")
	}
}

type testSrv struct {
	url   string
	close func()
}

func httpTestServer(t *testing.T, code int) testSrv {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
	})}
	go func() { _ = srv.Serve(ln) }()
	return testSrv{
		url:   fmt.Sprintf("http://%s", ln.Addr().String()),
		close: func() { _ = srv.Close() },
	}
}
