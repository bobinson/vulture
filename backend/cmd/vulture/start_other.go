//go:build !linux && !darwin && !freebsd

package main

import "os/exec"

// setupDaemonAttrs is a no-op on platforms that don't have Setsid.
// Vulture only officially supports Linux + macOS for install mode
// (Windows is Phase 2); this stub keeps the build working on other
// targets developers may compile-check against.
func setupDaemonAttrs(cmd *exec.Cmd) {}
