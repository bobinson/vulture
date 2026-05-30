package pluginlifecycle_test

// AC13 / D4 / MAJOR 6: install lockfile concurrency.
//
// Pinned signatures:
//   AcquireInstallLock(dir string) (release func(), err error)
//   AcquireInstallLockWithTimeout(dir string, timeout time.Duration) (release func(), err error)
//
// Invariants:
//   - MkdirAll(dir) happens BEFORE opening the lock file (so a non-existent
//     dir is created, not an error).
//   - Second concurrent acquirer blocks; with timeout, returns a typed error.
//   - Lock file path is <dir>/.install.lock with O_CREATE|O_RDWR (not O_EXCL).

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/vulture/backend/internal/pluginlifecycle"
)

func TestAcquireInstallLock_CreatesDir_MAJOR6(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("flock semantics differ on Windows")
	}
	root := t.TempDir()
	// Use a path that doesn't yet exist. AcquireInstallLock must
	// MkdirAll it before opening the lock file.
	dir := filepath.Join(root, "does", "not", "exist", "yet")
	release, err := pluginlifecycle.AcquireInstallLock(dir)
	if err != nil {
		t.Fatalf("AcquireInstallLock: %v", err)
	}
	defer release()
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir should exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".install.lock")); err != nil {
		t.Fatalf("lock file should exist: %v", err)
	}
}

func TestAcquireInstallLock_SecondAcquirerTimesOut_AC13(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("flock unavailable on Windows")
	}
	dir := t.TempDir()
	release, err := pluginlifecycle.AcquireInstallLock(dir)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer release()

	// Second acquirer in same process (or in this case, same goroutine
	// stack) should NOT succeed within the small timeout. Use the
	// bounded API.
	done := make(chan error, 1)
	go func() {
		r2, e := pluginlifecycle.AcquireInstallLockWithTimeout(dir, 50*time.Millisecond)
		if r2 != nil {
			r2()
		}
		done <- e
	}()

	select {
	case e := <-done:
		if e == nil {
			t.Fatalf("second acquirer unexpectedly succeeded")
		}
		if !errors.Is(e, pluginlifecycle.ErrLockTimeout) {
			t.Errorf("expected ErrLockTimeout sentinel, got %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second acquirer hung past 2s; timeout broken")
	}
}

func TestAcquireInstallLock_SerialSecondAcquirerSucceeds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("flock unavailable on Windows")
	}
	dir := t.TempDir()
	r1, err := pluginlifecycle.AcquireInstallLock(dir)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	r1() // release first

	r2, err := pluginlifecycle.AcquireInstallLockWithTimeout(dir, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("second acquire after release: %v", err)
	}
	r2()
}

func TestAcquireInstallLock_ReleaseIsIdempotent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("flock unavailable on Windows")
	}
	dir := t.TempDir()
	release, err := pluginlifecycle.AcquireInstallLock(dir)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	release()
	// Calling release a second time must not panic.
	release()
}
