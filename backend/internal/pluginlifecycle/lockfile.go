package pluginlifecycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/vulture/backend/pkg/pluginregistry"
)

// LockFilename is the file under PluginsDir used as the flock target.
const LockFilename = ".install.lock"

// defaultLockTimeout matches LLD D4: 30s is enough for one install to
// finish (cosign verify + a small disk write), short enough to fail
// fast in a CI loop.
const defaultLockTimeout = 30 * time.Second

// ErrLockTimeout signals that AcquireInstallLockWithTimeout could not
// take the lock within the supplied window.
var ErrLockTimeout = errors.New("install lock timed out")

// AcquireInstallLock waits up to defaultLockTimeout for the install
// lock. The release function unlocks + closes the underlying file
// descriptor.
func AcquireInstallLock(dir string) (func(), error) {
	return AcquireInstallLockWithTimeout(dir, defaultLockTimeout)
}

// AcquireInstallLockWithTimeout is the test-injection variant of
// AcquireInstallLock.
//
// MAJOR 6: MkdirAll runs BEFORE the lock file is opened (avoids a
// race where the dir doesn't yet exist on first install). The lock
// file is opened with O_CREATE|O_RDWR (not O_EXCL) so multiple
// invocations can serialise via flock rather than fight over file
// creation.
func AcquireInstallLockWithTimeout(dir string, timeout time.Duration) (func(), error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir lock dir: %w", err)
	}
	path := filepath.Join(dir, LockFilename)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, pluginregistry.StateFileMode)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	if err := flockWithTimeout(f, timeout); err != nil {
		f.Close()
		return nil, err
	}
	return makeReleaser(f), nil
}

// flockWithTimeout polls non-blocking flock until the timeout expires.
// Polling cadence is 50ms — short enough to feel responsive on serial
// re-acquire, long enough to keep CPU usage trivial during a contended
// 30s wait.
func flockWithTimeout(f *os.File, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("flock: %w", err)
		}
		if time.Now().After(deadline) {
			return ErrLockTimeout
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// makeReleaser wraps f.Close + LOCK_UN in a once-only closure so the
// release callback is safe to call multiple times (test contract).
func makeReleaser(f *os.File) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
		})
	}
}
