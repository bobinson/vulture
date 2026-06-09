package localdev

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAgentRuntime verifies the install-mode launcher wiring (0055 #10): in
// install mode agents resolve to the bundled venv + runtime/agents; in dev mode
// to the detected interpreter + the project tree.
func TestAgentRuntime(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "VERSION"), []byte("v0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VULTURE_HOME", home) // VERSION present -> ModeInstall

	l := &Launcher{cfg: &Config{ProjectRoot: "/proj"}, detect: &Detect{PythonPath: "/usr/bin/python3"}}

	py, dir := l.agentRuntime()
	if want := filepath.Join(home, "runtime", "python", "bin", "python3.12"); py != want {
		t.Errorf("install interpreter: got %q want %q", py, want)
	}
	if want := filepath.Join(home, "runtime", "agents"); dir != want {
		t.Errorf("install agentsDir: got %q want %q", dir, want)
	}

	// Dev mode: no VERSION -> ModeDev -> detected python + project tree.
	if err := os.Remove(filepath.Join(home, "VERSION")); err != nil {
		t.Fatal(err)
	}
	py, dir = l.agentRuntime()
	if py != "/usr/bin/python3" {
		t.Errorf("dev interpreter: got %q want /usr/bin/python3", py)
	}
	if want := filepath.Join("/proj", "agents"); dir != want {
		t.Errorf("dev agentsDir: got %q want %q", dir, want)
	}
}

// TestCheckInstallPrereqs_NoVenvIsSoft verifies install-mode prereqs never
// hard-fail when no bundled venv is present (CLI-only installs still run the
// backend + skills); agents are simply reported unavailable.
func TestCheckInstallPrereqs_NoVenvIsSoft(t *testing.T) {
	t.Setenv("VULTURE_HOME", t.TempDir()) // no runtime/python/bin/python3.12
	d, err := CheckInstallPrereqs()
	if err != nil {
		t.Fatalf("CheckInstallPrereqs hard-failed without a venv: %v", err)
	}
	if d.PythonPath != "" {
		t.Errorf("expected empty PythonPath without a venv, got %q", d.PythonPath)
	}
	if d.UvicornOK {
		t.Error("expected UvicornOK=false without a venv")
	}
}
