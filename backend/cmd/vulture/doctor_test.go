package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/localdev"
)

// TestCheckPythonInstallMissingIsWarn verifies that in install mode, a missing
// bundled Python interpreter is a WARN (CLI-only install is a documented-valid
// state), NOT a hard FAIL.
func TestCheckPythonInstallMissingIsWarn(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "VERSION"), []byte("v0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VULTURE_HOME", home) // ModeInstall, but no runtime/python/bin/python3.12

	c := checkPython(localdev.ModeInstall)
	if c.ok {
		t.Errorf("checkPython: expected ok=false when interpreter absent")
	}
	if !c.warn {
		t.Errorf("checkPython: expected warn=true (not a hard fail) when interpreter absent")
	}
}
