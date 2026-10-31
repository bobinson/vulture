package server

// Feature 0102: the agent proxy and the plugin supervisor share one view of the
// /run credentials, built once by NewWithRegistry. The token the supervisor
// hands a plugin's container must be the token the proxy presents to that
// plugin's /run, whether or not a shared token is configured: two separately
// built views would each draw their own random key, and every plugin /run
// would then be refused. The registry, not the agent's name, decides what is
// in-tree, so a VULTURE_PLUGIN_DIRS override named like an in-tree agent gets
// its own derived token and never the shared one.

import (
	"bytes"
	"context"
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
	"time"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/pkg/pluginregistry"
)

const wiringSharedToken = "server-wiring-shared-agent-token"

// wiringPlugins are the two container plugins the test supervises: the bundled
// semgrep plugin, and an env-dir plugin that overrides the in-tree cwe agent.
var wiringPlugins = []string{"semgrep", "cwe"}

func TestNewWithRegistry_ProxyAndSupervisorShareRunTokens(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the recording docker is a shell script")
	}
	for _, shared := range []string{wiringSharedToken, ""} {
		t.Run(fmt.Sprintf("shared_token_configured=%v", shared != ""), func(t *testing.T) {
			run := runAuditThroughServer(t, shared)
			for _, name := range wiringPlugins {
				assertSameRunToken(t, run, name, shared)
			}
		})
	}
}

// assertSameRunToken checks that the plugin name received, on /run, exactly
// the token the supervisor injected into its container, and that the token is
// that plugin's own: derived from the shared token when one is configured, and
// never the shared token itself.
func assertSameRunToken(t *testing.T, run wiringRun, name, shared string) {
	t.Helper()
	sent, ok := run.agents[name].token()
	fault := runTokenDeliveryFault(run.injected[name], sent, ok)
	if fault == "" {
		fault = sharedTokenFault(sent, name, shared)
	}
	if fault != "" {
		t.Errorf("%s: %s", name, fault)
	}
}

// runTokenDeliveryFault describes how the token the proxy sent (ok is false
// when it sent none) fails to match the one injected into the container, or
// is empty when they match.
func runTokenDeliveryFault(injected, sent string, ok bool) string {
	switch {
	case injected == "":
		return "the supervisor injected no run token into its container"
	case !ok:
		return "the proxy sent no run token to its /run"
	case sent != injected:
		return "the proxy's run token differs from the one injected into its container"
	}
	return ""
}

// sharedTokenFault describes how name's run token misuses the configured
// shared token, or is empty when it is name's own derived token. With no
// shared token configured there is nothing to misuse.
func sharedTokenFault(token, name, shared string) string {
	switch {
	case shared == "":
		return ""
	case token == shared:
		return "a plugin received the shared agent token"
	case token != pluginregistry.PluginRunToken(shared, name):
		return "the run token is not the one derived from the shared token"
	}
	return ""
}

// wiringRun is what one audit through the server left behind: the run token
// each container was started with, and the agent that served each plugin.
type wiringRun struct {
	injected map[string]string
	agents   map[string]*recordingAgent
}

// runAuditThroughServer builds the server over a registry holding the two
// container plugins, runs one audit of both through its HTTP API and returns
// what the supervisor and the agents recorded.
func runAuditThroughServer(t *testing.T, shared string) wiringRun {
	t.Helper()
	rec := setWiringEnv(t, shared)
	run := wiringRun{injected: map[string]string{}, agents: startWiringAgents(t)}
	runAudit(t, startWiringServer(t, shared, run.agents))
	for _, name := range wiringPlugins {
		run.injected[name] = injectedRunToken(t, rec, name)
	}
	return run
}

// setWiringEnv points every path the server writes at this test's own temp
// dirs (the seeded local-dev password included, which would otherwise land in
// the shared temp dir), enables the supervisor over the wiring plugins with the
// recording docker, and returns the directory where that docker records each
// container.
func setWiringEnv(t *testing.T, shared string) string {
	t.Helper()
	setAgentTokenEnv(t, shared)
	rec := t.TempDir()
	t.Setenv("VULTURE_HOME", t.TempDir())
	t.Setenv("VULTURE_LOCAL_DEV_PASSWORD_FILE", filepath.Join(t.TempDir(), "local-dev-password"))
	t.Setenv("VULTURE_SUPERVISOR_AUDITS_DIR", t.TempDir())
	t.Setenv("VULTURE_DISABLE_SUPERVISOR", "false")
	t.Setenv("VULTURE_PLUGINS", strings.Join(wiringPlugins, ","))
	t.Setenv("VULTURE_DOCKER_BINARY", writeContainerRecordingDocker(t, rec))
	return rec
}

// startWiringAgents starts one recording agent per wiring plugin. Each plugin
// is dispatched to its agent through the URL override, which wins over config
// and manifest, and over any value this process inherited.
func startWiringAgents(t *testing.T) map[string]*recordingAgent {
	t.Helper()
	agents := map[string]*recordingAgent{}
	for _, name := range wiringPlugins {
		agents[name] = startRecordingAgent(t)
		t.Setenv("VULTURE_AGENT_"+strings.ToUpper(name)+"_URL", agents[name].srv.URL)
	}
	return agents
}

// startWiringServer builds the server over the wiring registry, checks that
// its plugin supervisor runs, and returns the base URL of its HTTP API.
func startWiringServer(t *testing.T, shared string, agents map[string]*recordingAgent) string {
	t.Helper()
	srv, err := NewWithRegistry(wiringConfig(t, shared), wiringRegistry(t, agents))
	if err != nil {
		t.Fatalf("NewWithRegistry: %v", err)
	}
	if srv.Supervisor() == nil {
		t.Fatal("the plugin supervisor did not start")
	}
	t.Cleanup(func() { _ = srv.Supervisor().StopAll(context.Background()) })
	api := httptest.NewServer(srv.Handler())
	t.Cleanup(api.Close)
	return api.URL
}

// setAgentTokenEnv makes the process environment agree with the configured
// shared token, as config.Load would: set when one is configured, unset
// otherwise.
func setAgentTokenEnv(t *testing.T, shared string) {
	t.Helper()
	t.Setenv(pluginregistry.AgentTokenEnv, shared)
	if shared == "" {
		if err := os.Unsetenv(pluginregistry.AgentTokenEnv); err != nil {
			t.Fatalf("unset %s: %v", pluginregistry.AgentTokenEnv, err)
		}
	}
}

func wiringConfig(t *testing.T, shared string) *config.Config {
	t.Helper()
	return &config.Config{
		Port:       "0",
		ListenAddr: "127.0.0.1:0",
		DBPath:     filepath.Join(t.TempDir(), "wiring.db"),
		LocalMode:  true,
		JWTSecret:  strings.Repeat("w", 40),
		AgentToken: shared,
		Agents:     map[string]config.AgentConfig{},
	}
}

// wiringRegistry builds the registry the way production does, from the
// virtual in-tree entries, a builtin directory holding semgrep and an env
// directory whose cwe manifest overrides the in-tree cwe agent. Each plugin's
// port is its recording agent's, so the supervisor's health probe reaches
// nothing else on this host.
func wiringRegistry(t *testing.T, agents map[string]*recordingAgent) pluginregistry.Registry {
	t.Helper()
	builtin, envDir := t.TempDir(), t.TempDir()
	writeWiringManifest(t, builtin, "semgrep", "in-tree", agents["semgrep"].port())
	writeWiringManifest(t, envDir, "cwe", "user-supplied", agents["cwe"].port())
	reg, err := pluginregistry.Build(pluginregistry.LoadOptions{
		BuiltinDir:     builtin,
		ExtraDirs:      []string{envDir},
		IncludeVirtual: true,
		Logger:         log.New(io.Discard, "", 0),
	}, "")
	if err != nil {
		t.Fatalf("plugin registry: %v", err)
	}
	if p, ok := reg.ByName("cwe"); !ok || p.Source != "env:"+envDir {
		t.Fatalf("fixture: the env-dir cwe plugin must override the in-tree agent (ok=%v)", ok)
	}
	return reg
}

func writeWiringManifest(t *testing.T, root, name, tier string, port int) {
	t.Helper()
	manifest := fmt.Sprintf(`[plugin]
name        = %q
version     = "0.0.1"
api_version = "vulture-plugin/1.0"
publisher   = "vulture-test"
description = "Recording fixture for the run-token wiring test."

[trust]
tier         = %q
required_ack = ["network-egress"]

[runtime]
type            = "container"
image           = "ghcr.io/example/vulture-wiring-%s:0.0.1"
port            = %d
health_endpoint = "/health"

[[capabilities]]
phase = "scan"
emits = ["finding", "result"]
`, name, tier, name, port)
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugin.toml"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write %s manifest: %v", name, err)
	}
}

// writeContainerRecordingDocker writes a docker stand-in that records, for
// each `docker run`, its own environment in <dir>/<container name>.env. Every
// other command succeeds with no output, so images count as present.
func writeContainerRecordingDocker(t *testing.T, dir string) string {
	t.Helper()
	script := `#!/bin/sh
[ "$1" = run ] || exit 0
name=
prev=
for arg in "$@"; do
	[ "$prev" = --name ] && name=$arg
	prev=$arg
done
/usr/bin/env > "${0%/*}/$name.env"
echo wiring-container
`
	p := filepath.Join(dir, "docker")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("write recording docker: %v", err)
	}
	return p
}

// injectedRunToken is the VULTURE_AGENT_TOKEN the docker CLI held when it
// started name's container: the value its name-only `-e` copies in.
func injectedRunToken(t *testing.T, dir, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "vulture-agent-"+name+".env"))
	if err != nil {
		t.Fatalf("the supervisor never started the %s container: %v", name, err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, pluginregistry.AgentTokenEnv+"="); ok {
			return v
		}
	}
	return ""
}

// recordingAgent answers the supervisor's health probe and every /run with a
// completed run, and keeps the run-token headers each /run carried.
type recordingAgent struct {
	srv    *httptest.Server
	tokens chan []string
}

func startRecordingAgent(t *testing.T) *recordingAgent {
	t.Helper()
	a := &recordingAgent{tokens: make(chan []string, 8)}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		a.tokens <- r.Header.Values(pluginregistry.AgentTokenHeader)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: agent_start\ndata: {}\n\n"+
			"event: result\ndata: {\"findings\": [], \"summary\": \"done\", \"score\": 100}\n\n"+
			"event: agent_end\ndata: {\"status\": \"completed\"}\n\n")
	})
	a.srv = httptest.NewServer(mux)
	t.Cleanup(a.srv.Close)
	return a
}

func (a *recordingAgent) port() int { return a.srv.Listener.Addr().(*net.TCPAddr).Port }

// token reports the run token of the agent's first /run, and whether that
// /run carried one at all.
func (a *recordingAgent) token() (string, bool) {
	select {
	case values := <-a.tokens:
		if len(values) == 0 {
			return "", false
		}
		return values[0], true
	default:
		return "", false
	}
}

// runAudit submits a local source and one audit of every wiring plugin, and
// waits until the audit has finished.
func runAudit(t *testing.T, base string) {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	source := postWiringJSON(t, base+"/api/sources", map[string]any{"type": "local", "path": src})
	audit := postWiringJSON(t, base+"/api/audits", map[string]any{"source_id": source["id"], "types": wiringPlugins})
	waitForAuditEnd(t, base, fmt.Sprint(audit["id"]))
}

func postWiringJSON(t *testing.T, url string, body any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return decodeWiringJSON(t, resp, http.StatusCreated)
}

func decodeWiringJSON(t *testing.T, resp *http.Response, want int) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != want {
		t.Fatalf("%s %s: status %d (want %d), decode error %v", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want, err)
	}
	return out
}

func waitForAuditEnd(t *testing.T, base, id string) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		resp, err := http.Get(base + "/api/audits/" + id)
		if err != nil {
			t.Fatalf("GET audit: %v", err)
		}
		switch decodeWiringJSON(t, resp, http.StatusOK)["status"] {
		case "completed", "failed":
			return
		}
	}
	t.Fatalf("audit %s did not finish", id)
}
