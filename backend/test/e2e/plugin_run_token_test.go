//go:build e2e

package e2e

// Feature 0102: the /run credential the backend hands to agents and plugins.
//
// The in-tree agents share one token, VULTURE_AGENT_TOKEN. A plugin is a
// separately packaged container, so it must never hold that shared value: it
// gets a token of its own, hex(HMAC-SHA256(key=shared,
// msg="vulture-plugin-run-token/v1:"+name)), which opens that plugin and
// nothing else. The plugin receives it in its container environment, never on
// the docker command line, and the docker CLI itself runs without the
// backend's credentials or any dynamic-linker injection variable.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/server"
	"github.com/vulture/backend/internal/service"
	"github.com/vulture/backend/pkg/pluginregistry"
)

const (
	agentTokenEnv    = "VULTURE_AGENT_TOKEN"
	agentTokenHeader = "X-Vulture-Agent-Token"
	sharedAgentToken = "e2e-shared-agent-token-0102"
)

// derivedRunToken is the documented per-plugin token, computed here
// independently of the backend.
func derivedRunToken(shared, name string) string {
	mac := hmac.New(sha256.New, []byte(shared))
	mac.Write([]byte("vulture-plugin-run-token/v1:" + name))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestAgentProxy_SendsSharedTokenOnlyToInTreeAgents(t *testing.T) {
	t.Setenv(agentTokenEnv, sharedAgentToken)
	proxy := service.NewAgentProxyService(nil)

	// semgrep's expected value is the derived one, so equality also proves
	// it never received the shared token.
	for agentType, want := range map[string]string{
		"cwe":     sharedAgentToken,
		"owasp":   sharedAgentToken,
		"semgrep": derivedRunToken(sharedAgentToken, "semgrep"),
	} {
		if got := tokenSentTo(t, proxy, agentType); got != want {
			t.Errorf("%s received token %q, want %q", agentType, got, want)
		}
	}
}

// tokenSentTo dispatches one run of agentType to a recording agent and returns
// the token header that agent received ("" when none was sent).
func tokenSentTo(t *testing.T, proxy service.AgentProxyService, agentType string) string {
	t.Helper()
	received := make(chan string, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get(agentTokenHeader)
		w.Header().Set("Content-Type", "text/event-stream")
	}))
	defer agent.Close()

	events := make(chan *model.AgUIEvent, 16)
	err := proxy.RunAgent(context.Background(), agent.URL, agentType, "run-"+agentType,
		t.TempDir(), json.RawMessage(`{}`), events)
	if err != nil {
		t.Fatalf("dispatch %s: %v", agentType, err)
	}
	return <-received
}

func TestSupervisor_DeliversDerivedTokenOutsideArgv(t *testing.T) {
	t.Setenv(agentTokenEnv, sharedAgentToken)
	t.Setenv("VULTURE_JWT_SECRET", "e2e-jwt-secret-must-not-reach-docker")
	t.Setenv("LD_PRELOAD", "/nonexistent/vulture-e2e-preload.so")
	cfg := testConfig(t)
	cfg.AgentToken = sharedAgentToken

	run := superviseOnePlugin(t, cfg)

	if !hasPair(run.argv, "-e", agentTokenEnv) {
		t.Errorf("docker run argv lacks the name-only `-e %s`", agentTokenEnv)
	}
	if hasSubstring(run.argv, agentTokenEnv+"=") {
		t.Error("docker run argv carries a token value on the command line")
	}
	if run.cliEnv[agentTokenEnv] != derivedRunToken(sharedAgentToken, "semgrep") {
		t.Errorf("the docker CLI environment does not hold the derived semgrep token in %s", agentTokenEnv)
	}
	for _, name := range []string{"VULTURE_JWT_SECRET", "LD_PRELOAD"} {
		if _, ok := run.cliEnv[name]; ok {
			t.Errorf("the docker CLI environment carries %s", name)
		}
	}
	if strings.Contains(run.rawEnv, sharedAgentToken) || hasSubstring(run.argv, sharedAgentToken) {
		t.Error("the shared agent token reached the docker CLI")
	}
}

func TestSupervisor_LocalModeWithoutSharedTokenStillDeliversToken(t *testing.T) {
	t.Setenv(agentTokenEnv, "")
	if err := os.Unsetenv(agentTokenEnv); err != nil {
		t.Fatalf("unset %s: %v", agentTokenEnv, err)
	}
	cfg := testConfig(t)
	if !cfg.LocalMode {
		t.Fatal("this test needs a local-mode configuration")
	}
	cfg.AgentToken = ""

	tok, ok := superviseOnePlugin(t, cfg).containerEnv()[agentTokenEnv]
	if !ok || !isHex64(tok) {
		t.Fatalf("the plugin container gets no usable %s: present=%v, 64 lowercase hex=%v",
			agentTokenEnv, ok, isHex64(tok))
	}
}

// dockerRun is what the backend handed to `docker run`: the arguments, and
// the environment the docker CLI process itself was started with.
type dockerRun struct {
	argv   []string
	cliEnv map[string]string
	rawEnv string
}

// containerEnv resolves the environment docker gives the container:
// `-e NAME=VALUE` sets VALUE, and a bare `-e NAME` copies NAME from the
// docker CLI's own environment when it is set there.
func (r dockerRun) containerEnv() map[string]string {
	out := map[string]string{}
	for i := 0; i+1 < len(r.argv); i++ {
		if r.argv[i] != "-e" {
			continue
		}
		name, value, set := strings.Cut(r.argv[i+1], "=")
		if !set {
			value, set = r.cliEnv[name]
		}
		if set {
			out[name] = value
		}
	}
	return out
}

// superviseOnePlugin builds the backend over a registry holding one enabled
// container plugin, semgrep, and returns what the plugin supervisor handed to
// `docker run`. docker is a script that records its arguments and its own
// environment and otherwise succeeds.
func superviseOnePlugin(t *testing.T, cfg *config.Config) dockerRun {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the recording docker is a shell script")
	}
	rec := t.TempDir()
	t.Setenv("VULTURE_HOME", t.TempDir())
	t.Setenv("VULTURE_SUPERVISOR_AUDITS_DIR", t.TempDir())
	t.Setenv("VULTURE_DISABLE_SUPERVISOR", "false")
	t.Setenv("VULTURE_PLUGINS", "semgrep")
	t.Setenv("VULTURE_DOCKER_BINARY", writeRecordingDocker(t, rec))

	reg, err := pluginregistry.Build(pluginregistry.LoadOptions{
		BuiltinDir:     writeSemgrepManifest(t),
		IncludeVirtual: true,
		Logger:         log.New(io.Discard, "", 0),
	}, "")
	if err != nil {
		t.Fatalf("plugin registry: %v", err)
	}
	srv, err := server.NewWithRegistry(cfg, reg)
	if err != nil {
		t.Fatalf("server init: %v", err)
	}
	if srv.Supervisor() == nil {
		t.Fatal("the plugin supervisor did not start")
	}
	t.Cleanup(func() { _ = srv.Supervisor().StopAll(context.Background()) })
	return readDockerRun(t, rec)
}

// writeRecordingDocker writes the docker stand-in. It records only `docker
// run`, beside itself; ps, pull, rm and stop succeed with no output.
func writeRecordingDocker(t *testing.T, dir string) string {
	t.Helper()
	script := `#!/bin/sh
[ "$1" = run ] || exit 0
d=${0%/*}
printf '%s\n' "$@" > "$d/run.argv"
/usr/bin/env > "$d/run.env"
echo e2e-container
`
	p := filepath.Join(dir, "docker")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("write recording docker: %v", err)
	}
	return p
}

// writeSemgrepManifest writes a bundled-plugin manifest shaped like the real
// semgrep one and returns its builtin directory. Its port is a local server
// that answers the supervisor's health probe, so no probe reaches anything
// else on this host.
func writeSemgrepManifest(t *testing.T) string {
	t.Helper()
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(health.Close)
	port := health.Listener.Addr().(*net.TCPAddr).Port

	root := t.TempDir()
	dir := filepath.Join(root, "semgrep")
	manifest := fmt.Sprintf(`[plugin]
name        = "semgrep"
version     = "0.0.1"
api_version = "vulture-plugin/1.0"
publisher   = "vulture-core"
description = "Recording fixture for the plugin run-token tests."

[trust]
tier         = "in-tree"
required_ack = ["network-egress", "host-network"]

[runtime]
type            = "container"
image           = "ghcr.io/example/vulture-e2e-semgrep:0.0.1"
port            = %d
health_endpoint = "/health"
network         = "host"

[[capabilities]]
phase = "scan"
emits = ["finding", "result"]
`, port)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir plugin dir: %v", err)
	}
	mustWrite(t, filepath.Join(dir, "plugin.toml"), manifest)
	return root
}

func readDockerRun(t *testing.T, dir string) dockerRun {
	t.Helper()
	argv, err := os.ReadFile(filepath.Join(dir, "run.argv"))
	if err != nil {
		t.Fatalf("the supervisor never ran the plugin container: %v", err)
	}
	env, err := os.ReadFile(filepath.Join(dir, "run.env"))
	if err != nil {
		t.Fatalf("read the docker CLI environment: %v", err)
	}
	return dockerRun{
		argv:   strings.Split(strings.TrimSuffix(string(argv), "\n"), "\n"),
		cliEnv: parseEnvDump(string(env)),
		rawEnv: string(env),
	}
}

// parseEnvDump maps `env` output to NAME -> VALUE. Only single-line values
// are needed here; continuation lines of a multi-line value are ignored
// unless they happen to contain '=', which no asserted name relies on.
func parseEnvDump(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		if name, value, ok := strings.Cut(line, "="); ok {
			out[name] = value
		}
	}
	return out
}

func hasPair(argv []string, first, second string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == first && argv[i+1] == second {
			return true
		}
	}
	return false
}

func hasSubstring(argv []string, s string) bool {
	for _, arg := range argv {
		if strings.Contains(arg, s) {
			return true
		}
	}
	return false
}

func isHex64(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil && len(s) == 64 && s == strings.ToLower(s)
}
