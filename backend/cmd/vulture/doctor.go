package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/vulture/backend/internal/localdev"
)

// runDoctor implements `vulture doctor` (M8). Every check returns
// OK / WARN / FAIL with a one-line remediation. Exit codes: 0 if
// all OK, 1 on any FAIL, 2 on any WARN-only.
func runDoctor() {
	mode := localdev.DetectMode()
	failed := false
	warned := false

	type check struct {
		name string
		ok   bool
		warn bool
		fix  string
	}
	checks := []check{
		checkPython(mode),
		checkSymlink(mode),
		checkFileMode(filepath.Join(localdev.ConfigDir(mode, "."), ".env"), 0o600,
			"chmod 600 $VULTURE_HOME/config/.env"),
		checkFileMode(filepath.Join(localdev.DataDir(mode, "."), "vulture.db"), 0o600,
			"chmod 600 $VULTURE_HOME/data/vulture.db*"),
		checkAuditLog(mode),
	}
	fmt.Printf("vulture doctor (mode=%s)\n", mode)
	for _, c := range checks {
		status := "OK"
		if !c.ok {
			if c.warn {
				status = "WARN"
				warned = true
			} else {
				status = "FAIL"
				failed = true
			}
		}
		fmt.Printf("  [%s] %s\n", status, c.name)
		if !c.ok {
			fmt.Printf("    fix: %s\n", c.fix)
		}
	}
	if failed {
		os.Exit(1)
	}
	if warned {
		os.Exit(2)
	}
}

func checkPython(mode localdev.Mode) (c struct {
	name string
	ok   bool
	warn bool
	fix  string
}) {
	c.name = "Python runtime reachable"
	c.fix = "install Python 3.12+ and re-run the installer, or use Docker for agent scanning"
	bin := localdev.PythonBin(mode)
	if bin == "" {
		// Dev mode: skip (the launcher detects system python).
		c.ok = true
		return
	}
	if _, err := os.Stat(bin); err == nil {
		c.ok = true
		return
	}
	// Install mode with no bundled interpreter: a CLI-only install is a
	// documented-valid state (0055 plan line 544: WARN/exit 2), not a hard FAIL.
	c.warn = true
	return
}

func checkSymlink(mode localdev.Mode) (c struct {
	name string
	ok   bool
	warn bool
	fix  string
}) {
	c.name = "~/.local/bin/vulture symlink"
	c.fix = "ln -sf $VULTURE_HOME/bin/vulture ~/.local/bin/vulture"
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	link := filepath.Join(home, ".local", "bin", "vulture")
	if _, err := os.Lstat(link); err == nil {
		c.ok = true
	} else {
		c.warn = true
	}
	if mode == localdev.ModeDev {
		// Dev mode doesn't install a symlink; not a failure.
		c.ok = true
		c.warn = false
	}
	return
}

func checkFileMode(path string, want os.FileMode, fix string) (c struct {
	name string
	ok   bool
	warn bool
	fix  string
}) {
	c.name = "file mode on " + path
	c.fix = fix
	info, err := os.Stat(path)
	if err != nil {
		c.ok = true // file may not exist yet; skip
		return
	}
	if info.Mode().Perm() == want {
		c.ok = true
	}
	return
}

func checkAuditLog(mode localdev.Mode) (c struct {
	name string
	ok   bool
	warn bool
	fix  string
}) {
	c.name = "audit.log mode 0600"
	path := filepath.Join(localdev.DataDir(mode, "."), "logs", "audit.log")
	c.fix = "chmod 600 " + path
	info, err := os.Stat(path)
	if err != nil {
		c.ok = true // not yet created — not a failure
		return
	}
	if info.Mode().Perm() == 0o600 {
		c.ok = true
	}
	return
}
