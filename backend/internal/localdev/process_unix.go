//go:build linux || darwin || freebsd

package localdev

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the child in its own process group so the whole
// tree can be signalled as a unit.
//
// Feature 0069: without this, StopAll signalled only the direct child. A
// `sh -c` wrapper or a uvicorn worker survived as an orphan, kept the agent
// port bound, and kept the output pipes open — so `vulture stop` returned
// while the agents were still running, and a later `vulture start` collided
// with them. Setpgid also makes the child the group leader, which is what
// lets killGroup verify the group is ours before negating a pgid.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminateGroup asks the child's process group to exit.
func terminateGroup(cmd *exec.Cmd) error {
	return signalGroup(cmd, syscall.SIGTERM)
}

// killGroup forcibly terminates the child's process group.
func killGroup(cmd *exec.Cmd) error {
	return signalGroup(cmd, syscall.SIGKILL)
}

// signalGroup sends sig to the child's process group, but only when the child
// is the group leader — i.e. only to a group configureProcessGroup created.
// Otherwise it signals the child alone. Negating a pgid we did not establish
// would signal unrelated processes that happen to share the group, which for
// a foreground `vulture start` without job control means the caller's own
// shell pipeline.
func signalGroup(cmd *exec.Cmd, sig syscall.Signal) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	pid := cmd.Process.Pid
	pgid, err := syscall.Getpgid(pid)
	if err != nil || pgid != pid {
		return cmd.Process.Signal(sig)
	}
	return syscall.Kill(-pgid, sig)
}
