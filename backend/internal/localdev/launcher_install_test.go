package localdev

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// agentBuildProject is a project tree whose scripts/build.sh is a stub: it logs
// its arguments to buildLog and creates agents/.venv/bin/python3, a stub that
// exits venvExit for any call (so `import uvicorn` succeeds only on 0). The
// stub build itself exits buildExit.
type agentBuildProject struct {
	root, buildLog, venvPython string
}

func newAgentBuildProject(t *testing.T, buildExit, venvExit int) agentBuildProject {
	t.Helper()
	root := t.TempDir()
	p := agentBuildProject{
		root:       root,
		buildLog:   filepath.Join(root, "build.log"),
		venvPython: filepath.Join(root, "agents", ".venv", "bin", "python3"),
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "$@" >> %q
mkdir -p %q
printf '#!/bin/sh\nexit %d\n' > %q
chmod +x %q
exit %d
`, p.buildLog, filepath.Dir(p.venvPython), venvExit, p.venvPython, p.venvPython, buildExit)
	writeExecutable(t, filepath.Join(root, "scripts", "build.sh"), script)
	return p
}

// systemPython is a stub interpreter standing in for a system Python: it logs
// every call to the returned log path and fails.
func systemPython(t *testing.T) (python, callLog string) {
	t.Helper()
	dir := t.TempDir()
	callLog = filepath.Join(dir, "calls.log")
	python = filepath.Join(dir, "python3")
	writeExecutable(t, python, fmt.Sprintf("#!/bin/sh\necho \"$@\" >> %q\nexit 1\n", callLog))
	return python, callLog
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func readOrEmpty(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

// TestInstallAgentDeps_BuildsTheLockedVenv: with no uvicorn, dev mode builds the
// agents venv through scripts/build.sh agents (the hashed lockfile, nothing
// else) and switches to its interpreter. It never installs into the interpreter
// it found: a system Python would take packages from the index, unpinned.
func TestInstallAgentDeps_BuildsTheLockedVenv(t *testing.T) {
	p := newAgentBuildProject(t, 0, 0)
	sysPy, sysLog := systemPython(t)
	l := &Launcher{cfg: &Config{ProjectRoot: p.root}, detect: &Detect{PythonPath: sysPy}}

	if err := l.installAgentDeps(context.Background()); err != nil {
		t.Fatalf("installAgentDeps: %v", err)
	}
	if got := strings.TrimSpace(readOrEmpty(t, p.buildLog)); got != "agents" {
		t.Errorf("build.sh calls = %q, want one call with \"agents\"", got)
	}
	if l.detect.PythonPath != p.venvPython {
		t.Errorf("PythonPath = %q, want the built venv's %q", l.detect.PythonPath, p.venvPython)
	}
	if !l.detect.UvicornOK {
		t.Error("UvicornOK = false after a successful build")
	}
	if calls := readOrEmpty(t, sysLog); calls != "" {
		t.Errorf("the found interpreter was run (it must never install anything):\n%s", calls)
	}
}

// TestInstallAgentDeps_SkipsWhenUvicornImports: a ready interpreter builds nothing.
func TestInstallAgentDeps_SkipsWhenUvicornImports(t *testing.T) {
	p := newAgentBuildProject(t, 0, 0)
	l := &Launcher{cfg: &Config{ProjectRoot: p.root}, detect: &Detect{PythonPath: "/ready/python3", UvicornOK: true}}

	if err := l.installAgentDeps(context.Background()); err != nil {
		t.Fatalf("installAgentDeps: %v", err)
	}
	if calls := readOrEmpty(t, p.buildLog); calls != "" {
		t.Errorf("build.sh ran although uvicorn imports: %q", calls)
	}
	if l.detect.PythonPath != "/ready/python3" {
		t.Errorf("PythonPath changed to %q", l.detect.PythonPath)
	}
}

// TestInstallAgentDeps_FailuresAreFatal: a failed build, or a build after which
// uvicorn still does not import, stops the launch.
func TestInstallAgentDeps_FailuresAreFatal(t *testing.T) {
	for name, exits := range map[string][2]int{"build fails": {1, 0}, "uvicorn still missing": {0, 1}} {
		t.Run(name, func(t *testing.T) {
			p := newAgentBuildProject(t, exits[0], exits[1])
			sysPy, _ := systemPython(t)
			l := &Launcher{cfg: &Config{ProjectRoot: p.root}, detect: &Detect{PythonPath: sysPy}}

			if err := l.installAgentDeps(context.Background()); err == nil {
				t.Fatal("installAgentDeps succeeded; want an error")
			}
			if l.detect.UvicornOK {
				t.Error("UvicornOK = true after a failure")
			}
		})
	}
}
