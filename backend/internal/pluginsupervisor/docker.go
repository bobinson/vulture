// Package pluginsupervisor manages the lifecycle of container-runtime
// plugins discovered by pluginregistry. See feature 0052 LLD.
package pluginsupervisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// DockerClient is the subset of `docker` CLI capability the supervisor
// needs. Injectable so tests can drive it with a fake.
type DockerClient interface {
	Pull(ctx context.Context, image string) error
	Inspect(ctx context.Context, image string) (bool, error)
	Run(ctx context.Context, argv []string) (containerID string, err error)
	Stop(ctx context.Context, name string, timeout time.Duration) error
	Remove(ctx context.Context, name string) error
	PS(ctx context.Context) ([]RunningContainer, error)
	Info(ctx context.Context) error
}

// RunningContainer is the (Name, Image, Status) tuple returned by
// `docker ps --filter name=vulture-agent-`.
type RunningContainer struct {
	Name   string
	Image  string
	Status string
}

// DockerOptions configures the exec-based docker client.
type DockerOptions struct {
	// Binary is the docker executable path. If empty, the env var
	// VULTURE_DOCKER_BINARY is consulted; falling back to a PATH
	// lookup of "docker".
	Binary string
}

// Sentinel errors. Callers should check via errors.Is.
var (
	ErrDockerNotFound = errors.New("docker binary not found")
	ErrDockerFailed   = errors.New("docker command failed")
)

// NewDockerClient constructs the default exec-based DockerClient.
func NewDockerClient(opts DockerOptions) DockerClient {
	return &dockerExec{binaryHint: opts.Binary}
}

type dockerExec struct {
	binaryHint string
}

// resolveBinary mirrors the pattern in internal/cosign/verify.go:
// explicit field > env var > PATH.
func (d *dockerExec) resolveBinary() (string, error) {
	if d.binaryHint != "" {
		if _, err := os.Stat(d.binaryHint); err != nil {
			return "", fmt.Errorf("%w: %s", ErrDockerNotFound, d.binaryHint)
		}
		return d.binaryHint, nil
	}
	if env := os.Getenv("VULTURE_DOCKER_BINARY"); env != "" {
		if _, err := os.Stat(env); err != nil {
			return "", fmt.Errorf("%w: %s", ErrDockerNotFound, env)
		}
		return env, nil
	}
	p, err := exec.LookPath("docker")
	if err != nil {
		return "", fmt.Errorf("%w: not on PATH (set VULTURE_DOCKER_BINARY or install docker)", ErrDockerNotFound)
	}
	return p, nil
}

// run executes argv against the resolved binary and returns
// (stdout, stderr, error). A non-zero exit is wrapped in ErrDockerFailed.
func (d *dockerExec) run(ctx context.Context, argv []string) (string, string, error) {
	binary, err := d.resolveBinary()
	if err != nil {
		return "", "", err
	}
	cmd := exec.CommandContext(ctx, binary, argv...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	runErr := cmd.Run()
	if runErr != nil {
		return outBuf.String(), errBuf.String(),
			fmt.Errorf("%w: %s: %s", ErrDockerFailed, strings.TrimSpace(errBuf.String()), runErr)
	}
	return outBuf.String(), errBuf.String(), nil
}

func (d *dockerExec) Pull(ctx context.Context, image string) error {
	_, _, err := d.run(ctx, []string{"pull", image})
	return err
}

func (d *dockerExec) Inspect(ctx context.Context, image string) (bool, error) {
	_, _, err := d.run(ctx, []string{"image", "inspect", image})
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ErrDockerNotFound) {
		return false, err
	}
	// Non-zero exit means image not present locally; that's not a hard error.
	return false, nil
}

func (d *dockerExec) Run(ctx context.Context, argv []string) (string, error) {
	stdout, _, err := d.run(ctx, argv)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout), nil
}

func (d *dockerExec) Stop(ctx context.Context, name string, timeout time.Duration) error {
	secs := int(timeout / time.Second)
	if secs < 1 {
		secs = 1
	}
	_, _, err := d.run(ctx, []string{"stop", "--time", strconv.Itoa(secs), name})
	return err
}

// Remove force-removes a container by name. Used before `docker run
// --name` to clear a stale stopped container of the same name (a prior
// StopAll leaves containers stopped, not removed). "no such container"
// is benign — the caller ignores the error.
func (d *dockerExec) Remove(ctx context.Context, name string) error {
	_, _, err := d.run(ctx, []string{"rm", "-f", name})
	return err
}

func (d *dockerExec) Info(ctx context.Context) error {
	_, _, err := d.run(ctx, []string{"info"})
	return err
}

func (d *dockerExec) PS(ctx context.Context) ([]RunningContainer, error) {
	argv := []string{
		"ps",
		"--filter", "name=vulture-agent-",
		"--format", "{{.Names}}\t{{.Image}}\t{{.Status}}",
	}
	stdout, _, err := d.run(ctx, argv)
	if err != nil {
		return nil, err
	}
	return parsePSOutput(stdout), nil
}

// parsePSOutput is a separate function to keep PS small and testable.
// Accepts either tab-separated (production docker output) or pipe-
// separated (the test mock writes |-delimited output to avoid shell
// escaping pain).
func parsePSOutput(raw string) []RunningContainer {
	// Normalise common literal-escape sequences emitted by simple
	// shell mocks. Real docker output uses real newlines/tabs so
	// these no-ops on production traffic.
	raw = strings.ReplaceAll(raw, `\n`, "\n")
	raw = strings.ReplaceAll(raw, `\t`, "\t")
	out := make([]RunningContainer, 0)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := splitPSLine(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "vulture-agent-") {
			continue
		}
		rc := RunningContainer{Name: fields[0]}
		if len(fields) > 1 {
			rc.Image = fields[1]
		}
		if len(fields) > 2 {
			rc.Status = fields[2]
		}
		out = append(out, rc)
	}
	return out
}

func splitPSLine(line string) []string {
	if strings.Contains(line, "\t") {
		return strings.Split(line, "\t")
	}
	if strings.Contains(line, "|") {
		return strings.Split(line, "|")
	}
	return []string{line}
}
