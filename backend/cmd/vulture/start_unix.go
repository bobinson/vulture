//go:build linux || darwin || freebsd

package main

import (
	"os/exec"
	"syscall"
)

// setupDaemonAttrs detaches the spawned child from the current TTY
// and puts it in its own process group so `vulture stop` can signal
// the whole tree. See plan invariant S4 (process-group cascade).
func setupDaemonAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}
