//go:build !(linux || darwin || freebsd)

package localdev

import "os/exec"

// Process groups are a POSIX concept; on other platforms fall back to
// signalling the child alone. Feature 0069's spawn verification (port
// preflight, readiness poll, log sink) is platform-neutral and still applies.

func configureProcessGroup(_ *exec.Cmd) {}

func terminateGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

func killGroup(cmd *exec.Cmd) error {
	return terminateGroup(cmd)
}
