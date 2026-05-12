package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vulture/backend/internal/localdev"
)

// runStop implements `vulture stop` with PID-reuse mitigation (S4).
// Before sending any signal it reads /proc/<pid>/cmdline (Linux) or
// runs `ps -p <pid> -o command=` (macOS) and confirms the target
// process is in fact a vulture instance. PID files pointing at
// reused PIDs are deleted with a warning and no signal is sent.
func runStop() {
	mode := localdev.DetectMode()
	runDir := filepath.Join(localdev.DataDir(mode, "."), "run")
	entries, err := os.ReadDir(runDir)
	if err != nil {
		fmt.Println("no running daemon (run dir absent)")
		return
	}
	stopped := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pid") {
			continue
		}
		if stopOnePID(filepath.Join(runDir, e.Name())) {
			stopped++
		}
	}
	fmt.Printf("vulture stop: signaled %d process(es)\n", stopped)
}

func stopOnePID(pidFile string) bool {
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		_ = os.Remove(pidFile)
		return false
	}
	if !isVultureProcess(pid) {
		fmt.Fprintf(os.Stderr,
			"warning: PID %d (from %s) is not a vulture process; removing stale PID file\n",
			pid, filepath.Base(pidFile))
		_ = os.Remove(pidFile)
		return false
	}
	// Signal the process group so any spawned agents come down too.
	pgid, err := syscall.Getpgid(pid)
	target := -pgid
	if err != nil {
		target = pid
	}
	_ = syscall.Kill(target, syscall.SIGTERM)
	if waitGone(pid, 10*time.Second) {
		_ = os.Remove(pidFile)
		return true
	}
	_ = syscall.Kill(target, syscall.SIGKILL)
	_ = os.Remove(pidFile)
	return true
}

// waitGone polls until the process is dead, up to the timeout.
// Returns true if the process is gone, false if the timeout expired.
func waitGone(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return syscall.Kill(pid, 0) != nil
}
