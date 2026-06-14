package localdev

import (
	"os"
	"path/filepath"
	"testing"
)

// TestUIPort verifies the UI port resolution: install mode serves the SPA from
// the backend port (single server); dev mode serves the UI from the vite
// frontend port.
func TestUIPort(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "VERSION"), []byte("v0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VULTURE_HOME", home) // VERSION present -> ModeInstall

	cfg := &Config{BackendPort: "28080", FrontendPort: "23001"}

	if got := UIPort(ModeInstall, cfg); got != "28080" {
		t.Errorf("UIPort(install) = %q, want backend port 28080", got)
	}
	if got := UIPort(ModeDev, cfg); got != "23001" {
		t.Errorf("UIPort(dev) = %q, want frontend port 23001", got)
	}
}
