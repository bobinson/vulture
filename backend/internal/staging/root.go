package staging

import (
	"fmt"
	"os"
)

// rootMode lets a plugin container, which mounts the root read-only and may
// run as a different user, read the trees staged under it.
const rootMode = 0o755

// EnsureRoot creates the staging root as the calling (backend) user and
// checks the backend can create audit directories in it.
//
// It must run before the plugin supervisor starts any container: the root is
// a bind-mount source, and Docker creates a missing mount source as root.
// A root-owned root locks a non-root dev backend out of staging, so every
// plugin is skipped with "mkdir …: permission denied" and the audit fails.
// An existing root keeps its mode; only one this call creates is set to
// rootMode, independent of the process umask.
func EnsureRoot(dir string) error {
	if err := createRoot(dir); err != nil {
		return rootError(dir, err)
	}
	return probeWritable(dir)
}

func createRoot(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, rootMode); err != nil {
		return err
	}
	return os.Chmod(dir, rootMode)
}

// probeWritable creates and removes a directory the way staging an audit
// does, so a root that exists but belongs to another user is caught at
// startup rather than on the first plugin audit.
func probeWritable(dir string) error {
	probe, err := os.MkdirTemp(dir, ".write-probe-")
	if err != nil {
		return rootError(dir, err)
	}
	return os.Remove(probe)
}

func rootError(dir string, err error) error {
	return fmt.Errorf("plugin staging root %s is not writable by this backend (uid %d): %w; "+
		"plugin agents will be skipped until it is: remove or chown it so the backend user owns it, "+
		"or point VULTURE_SUPERVISOR_AUDITS_DIR at a writable directory", dir, os.Getuid(), err)
}
