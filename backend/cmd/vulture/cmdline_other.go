//go:build !linux && !darwin

package main

// isVultureProcess fallback for unsupported platforms. Install mode
// targets Linux + macOS only; Windows is Phase 2. Returning false
// here means `vulture stop` will refuse to signal anything — safe
// default for an unsupported build target.
func isVultureProcess(pid int) bool { return false }
