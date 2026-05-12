package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/vulture/backend/internal/localdev"
)

// runStart implements `vulture start` for install mode (S2). Binds
// the backend to 127.0.0.1, daemonizes (unless --foreground), and
// writes a PID file to data/run/backend.pid (mode 0600).
//
// In dev mode `vulture start` is a thin alias for `vulture
// local_start` (foreground) — there's no daemonization in dev.
func runStart() {
	args := os.Args[2:]
	foreground := hasFlag(args, "--foreground") || hasFlag(args, "--no-detach")
	allowNet := hasFlag(args, "--unsafe-allow-network")
	yes := hasFlag(args, "--yes")

	if allowNet && os.Getenv("VULTURE_LOCAL_MODE") == "true" {
		fmt.Fprintln(os.Stderr,
			"refusing to start: --unsafe-allow-network is incompatible with VULTURE_LOCAL_MODE=true (S2)")
		os.Exit(1)
	}
	if allowNet && !yes {
		fmt.Fprintln(os.Stderr,
			"--unsafe-allow-network exposes the daemon on the LAN. Re-run with --yes to confirm.")
		os.Exit(1)
	}

	bindAddr := "127.0.0.1"
	if allowNet {
		bindAddr = "0.0.0.0"
		fmt.Fprintln(os.Stderr, "WARNING: --unsafe-allow-network: daemon listening on 0.0.0.0; "+
			"VULTURE_LOCAL_MODE=true is incompatible with this flag.")
	}

	mode := localdev.DetectMode()
	if mode == localdev.ModeDev {
		// In dev mode, just delegate to local_start which already
		// runs foreground.
		runLocalStart()
		return
	}

	pidPath := filepath.Join(localdev.DataDir(mode, ""), "run", "backend.pid")
	if err := os.MkdirAll(filepath.Dir(pidPath), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir run dir: %v\n", err)
		os.Exit(1)
	}

	if foreground {
		// Foreground: just run local_start with the bind address
		// applied via env.
		_ = os.Setenv("VULTURE_BIND_ADDR", bindAddr)
		writePIDFile(pidPath, os.Getpid())
		runLocalStart()
		return
	}

	// Detach: spawn ourselves with --foreground and exit.
	bin, _ := os.Executable()
	cmd := exec.Command(bin, "start", "--foreground")
	cmd.Env = append(os.Environ(), "VULTURE_BIND_ADDR="+bindAddr)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	setupDaemonAttrs(cmd)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start: %v\n", err)
		os.Exit(1)
	}
	writePIDFile(pidPath, cmd.Process.Pid)
	fmt.Printf("vulture daemon started (pid %d), bind=%s\n", cmd.Process.Pid, bindAddr)
	fmt.Printf("UI: http://%s:23000/\n", bindAddr)
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func writePIDFile(path string, pid int) {
	_ = os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0o600)
}
