//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// isVultureProcess on macOS shells out to `ps` because /proc is not
// available. The ps invocation has no user-supplied data so there's
// no shell-injection surface. See plan invariant S4.
func isVultureProcess(pid int) bool {
	out, err := exec.Command("ps", "-p", fmt.Sprintf("%d", pid), "-o", "command=").Output()
	if err != nil {
		return false
	}
	cmd := strings.ToLower(strings.TrimSpace(string(out)))
	if cmd == "" {
		return false
	}
	for _, kw := range []string{"vulture", "python", "uvicorn"} {
		if strings.Contains(cmd, kw) {
			return true
		}
	}
	return false
}
