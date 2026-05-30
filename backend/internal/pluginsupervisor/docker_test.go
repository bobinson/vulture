package pluginsupervisor_test

// RED tests for the DockerClient exec wrapper (same shape as 0051's
// cosign.Verify). Tests use a shell-script mock docker pointed at via
// VULTURE_DOCKER_BINARY.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/pluginsupervisor"
)

func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script mock docker unsupported on Windows")
	}
}

// writeMockDocker writes an executable shell script at <dir>/docker
// that:
//   - records argv to <dir>/argv.log (one arg per line, '---' delimiter
//     between invocations)
//   - if first arg is "ps": prints psOutput on stdout
//   - if first arg is "run": prints "container-id-<image>" on stdout
//   - else prints body on stdout
//   - prints errBody on stderr
//   - exits with `code`
func writeMockDocker(t *testing.T, dir, body, errBody, psOutput string, code int) string {
	t.Helper()
	script := `#!/bin/sh
{
  echo "---"
  for a in "$@"; do
    echo "$a"
  done
} >> "` + filepath.Join(dir, "argv.log") + `"

case "$1" in
  ps)
    printf '%s' "` + psOutput + `"
    exit 0
    ;;
  run)
    last=""
    for a in "$@"; do last="$a"; done
    echo "container-id-$last"
    exit ` + intToStr(code) + `
    ;;
esac
echo "` + body + `"
echo "` + errBody + `" >&2
exit ` + intToStr(code) + `
`
	p := filepath.Join(dir, "docker")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("write mock docker: %v", err)
	}
	return p
}

func intToStr(i int) string {
	switch i {
	case 0:
		return "0"
	case 1:
		return "1"
	}
	return "0"
}

func TestDockerClient_Pull_RunsBinary(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	bin := writeMockDocker(t, dir, "pulled", "", "", 0)
	t.Setenv("VULTURE_DOCKER_BINARY", bin)

	dc := pluginsupervisor.NewDockerClient(pluginsupervisor.DockerOptions{})
	if err := dc.Pull(context.Background(), "ghcr.io/x/y:1"); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	logBytes, _ := os.ReadFile(filepath.Join(dir, "argv.log"))
	log := string(logBytes)
	if !strings.Contains(log, "pull") || !strings.Contains(log, "ghcr.io/x/y:1") {
		t.Errorf("expected argv to include pull and image; argv.log=\n%s", log)
	}
}

func TestDockerClient_Run_ReturnsContainerID(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	bin := writeMockDocker(t, dir, "", "", "", 0)
	t.Setenv("VULTURE_DOCKER_BINARY", bin)

	dc := pluginsupervisor.NewDockerClient(pluginsupervisor.DockerOptions{})
	id, err := dc.Run(context.Background(), []string{"run", "-d", "ghcr.io/x/y:1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(id, "container-id-") {
		t.Errorf("Run returned %q; expected container-id-<image>", id)
	}
}

func TestDockerClient_Stop_PassesTimeout(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	bin := writeMockDocker(t, dir, "stopped", "", "", 0)
	t.Setenv("VULTURE_DOCKER_BINARY", bin)

	dc := pluginsupervisor.NewDockerClient(pluginsupervisor.DockerOptions{})
	if err := dc.Stop(context.Background(), "vulture-agent-foo", 10*time.Second); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	logBytes, _ := os.ReadFile(filepath.Join(dir, "argv.log"))
	log := string(logBytes)
	if !strings.Contains(log, "stop") {
		t.Errorf("expected 'stop' in argv; argv.log=\n%s", log)
	}
	if !strings.Contains(log, "--time") || !strings.Contains(log, "10") {
		t.Errorf("expected --time 10 in argv; argv.log=\n%s", log)
	}
	if !strings.Contains(log, "vulture-agent-foo") {
		t.Errorf("expected container name in argv; argv.log=\n%s", log)
	}
}

func TestDockerClient_PS_FiltersVultureAgents(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	// PS output one container per line (format pinned by NewDockerClient).
	psOut := "vulture-agent-foo|ghcr.io/x/foo:1\\nvulture-agent-bar|ghcr.io/x/bar:1"
	bin := writeMockDocker(t, dir, "", "", psOut, 0)
	t.Setenv("VULTURE_DOCKER_BINARY", bin)

	dc := pluginsupervisor.NewDockerClient(pluginsupervisor.DockerOptions{})
	rcs, err := dc.PS(context.Background())
	if err != nil {
		t.Fatalf("PS: %v", err)
	}
	// We don't pin the exact parse format too tightly — the contract
	// here is "returns one entry per vulture-agent-* container".
	if len(rcs) < 1 {
		t.Errorf("expected at least 1 running container; got %d", len(rcs))
	}
	if len(rcs) > 0 && !strings.HasPrefix(rcs[0].Name, "vulture-agent-") {
		t.Errorf("PS returned non-vulture container: %+v", rcs[0])
	}
}

func TestDockerClient_BinaryMissing_TypedError(t *testing.T) {
	t.Setenv("VULTURE_DOCKER_BINARY", "/definitely/nonexistent/docker")
	dc := pluginsupervisor.NewDockerClient(pluginsupervisor.DockerOptions{})
	err := dc.Pull(context.Background(), "ghcr.io/x/y:1")
	if err == nil {
		t.Fatalf("expected error for missing binary")
	}
	if !errors.Is(err, pluginsupervisor.ErrDockerNotFound) {
		t.Errorf("expected ErrDockerNotFound; got %v", err)
	}
}

func TestDockerClient_ExecNonZero_ErrorContainsStderr(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	bin := writeMockDocker(t, dir, "", "BOOM-stderr", "", 1)
	t.Setenv("VULTURE_DOCKER_BINARY", bin)

	dc := pluginsupervisor.NewDockerClient(pluginsupervisor.DockerOptions{})
	err := dc.Pull(context.Background(), "ghcr.io/x/y:1")
	if err == nil {
		t.Fatalf("expected error on non-zero exit")
	}
	if !strings.Contains(err.Error(), "BOOM-stderr") {
		t.Errorf("error should embed stderr; got %v", err)
	}
}

func TestDockerClient_EnvVarOverridesBinary(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	bin := writeMockDocker(t, dir, "ok", "", "", 0)
	t.Setenv("VULTURE_DOCKER_BINARY", bin)

	dc := pluginsupervisor.NewDockerClient(pluginsupervisor.DockerOptions{})
	if err := dc.Pull(context.Background(), "ghcr.io/x/y:1"); err != nil {
		t.Fatalf("Pull via env-overridden binary: %v", err)
	}
}
