//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
)

// isVultureProcess returns true if pid belongs to a running process
// whose cmdline begins with "vulture" or "python" (agent
// subprocess). The check reads /proc/<pid>/cmdline directly — POSIX
// `ps` is avoided to keep the check tamper-resistant in test
// scenarios that may stub PATH.
func isVultureProcess(pid int) bool {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	// cmdline is NUL-separated; convert to space-separated for prefix
	// matching.
	args := strings.ReplaceAll(string(raw), "\x00", " ")
	args = strings.TrimSpace(args)
	if args == "" {
		return false
	}
	argv0 := strings.ToLower(args)
	for _, prefix := range []string{"vulture", "python", "uvicorn"} {
		if strings.HasPrefix(argv0, prefix) || strings.Contains(argv0, "/vulture ") ||
			strings.Contains(argv0, "/python ") {
			return true
		}
	}
	return false
}
