package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vulture/backend/internal/localdev"
)

// runUninstall implements `vulture uninstall [--yes] [--keep-data]`.
// Refuses to operate in dev mode. Removes only what install.sh
// created — VULTURE_HOME and the ~/.local/bin/vulture symlink IF
// that symlink points into VULTURE_HOME.
func runUninstall() {
	mode := localdev.DetectMode()
	if mode != localdev.ModeInstall {
		fmt.Fprintln(os.Stderr,
			"uninstall only applies to an installed vulture (mode=install). "+
				"For dev mode, just delete your source checkout.")
		os.Exit(1)
	}
	args := os.Args[2:]
	yes := false
	keepData := false
	for _, a := range args {
		switch a {
		case "--yes", "-y":
			yes = true
		case "--keep-data":
			keepData = true
		}
	}
	home := localdev.ResolveHome()
	if !confirm(yes, home, keepData) {
		fmt.Println("uninstall aborted.")
		return
	}
	// Stop any running daemon first.
	runStop()
	// Remove the symlink if it points into VULTURE_HOME.
	removeSymlink(home)
	// Remove the install tree.
	if keepData {
		removeWithKeepData(home)
	} else {
		_ = os.RemoveAll(home)
	}
	fmt.Println("uninstall complete.")
}

func confirm(yes bool, home string, keep bool) bool {
	if yes {
		return true
	}
	msg := "Remove " + home
	if keep {
		msg += " (preserving data/)"
	}
	msg += " ? [y/N] "
	fmt.Print(msg)
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return false
	}
	ans := strings.TrimSpace(strings.ToLower(sc.Text()))
	return ans == "y" || ans == "yes"
}

func removeSymlink(home string) {
	userHome, err := os.UserHomeDir()
	if err != nil {
		return
	}
	link := filepath.Join(userHome, ".local", "bin", "vulture")
	target, err := os.Readlink(link)
	if err != nil {
		return
	}
	if !strings.HasPrefix(target, home) {
		fmt.Fprintf(os.Stderr,
			"skipping %s: symlink target %q is not inside %s; remove it manually if intended\n",
			link, target, home)
		return
	}
	_ = os.Remove(link)
}

func removeWithKeepData(home string) {
	// Remove everything except data/.
	entries, err := os.ReadDir(home)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Name() == "data" {
			continue
		}
		_ = os.RemoveAll(filepath.Join(home, e.Name()))
	}
}
