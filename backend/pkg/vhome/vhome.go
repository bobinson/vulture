// Package vhome resolves the Vulture home directory and detects whether
// Vulture is running as a native install (Mode E) versus a source checkout.
//
// This is the single source of truth for that rule, shared across modules:
// the backend consumes it via internal/localdev (which wraps it in the
// localdev.Mode type), and the CLI consumes it directly. It deliberately
// lives in pkg/ (not internal/) so github.com/vulture/cli — a separate
// module — can import it; internal/localdev is unreachable from there.
package vhome

import (
	"os"
	"path/filepath"
)

// Home returns the VULTURE_HOME path. Honors the env var first, then falls
// back to $HOME/.vulture. Returns "" only if neither is available, which
// callers treat as "not a native install" (dev mode).
func Home() string {
	if h := os.Getenv("VULTURE_HOME"); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".vulture")
}

// IsInstall reports whether a native install is present, i.e. a VERSION file
// exists at the resolved home. Errors during stat (missing home, unreadable)
// are treated as "not installed".
func IsInstall() bool {
	home := Home()
	if home == "" {
		return false
	}
	info, err := os.Stat(filepath.Join(home, "VERSION"))
	if err != nil || info.IsDir() {
		return false
	}
	return true
}
