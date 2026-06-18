package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// fakePluginReg is a minimal pluginregistry.Registry for handler tests.
type fakePluginReg struct{ plugins []pluginregistry.Plugin }

func (f fakePluginReg) All() []pluginregistry.Plugin { return f.plugins }
func (f fakePluginReg) Enabled() []pluginregistry.Plugin {
	out := make([]pluginregistry.Plugin, 0, len(f.plugins))
	for _, p := range f.plugins {
		if p.Enabled {
			out = append(out, p)
		}
	}
	return out
}
func (f fakePluginReg) ByName(name string) (pluginregistry.Plugin, bool) {
	for _, p := range f.plugins {
		if p.Name() == name {
			return p, true
		}
	}
	return pluginregistry.Plugin{}, false
}

func mkPlugin(name, display string, enabled bool) pluginregistry.Plugin {
	return pluginregistry.Plugin{
		Enabled: enabled,
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{Name: name, DisplayName: display},
		},
	}
}

// G1: /api/agents must surface ENABLED registry plugins (e.g. semgrep) in
// addition to the built-in agents — without duplicating the built-ins (which
// the registry also carries as in-tree virtual plugins) and without listing
// DISABLED plugins.
func TestAgentHandlerList_IncludesEnabledPlugins(t *testing.T) {
	agents := map[string]config.AgentConfig{
		"chaos": {Name: "Chaos Engineering", Type: "chaos", URL: ""}, // empty URL -> fast "unknown"
	}
	h := NewAgentHandler(agents)
	reg := fakePluginReg{plugins: []pluginregistry.Plugin{
		mkPlugin("chaos", "Chaos Engineering", true),  // in-tree virtual — must dedupe
		mkPlugin("semgrep", "Semgrep (bundled)", true), // external, enabled — must appear
		mkPlugin("disabledtool", "Disabled Tool", false), // disabled — must NOT appear
	}}
	h.SetPluginRegistry(reg, func(pluginregistry.Plugin) string { return "" })

	req := httptest.NewRequest("GET", "/api/agents", nil)
	w := httptest.NewRecorder()
	h.List(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var infos []model.AgentInfo
	if err := json.NewDecoder(w.Body).Decode(&infos); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byType := map[string]int{}
	var semgrep *model.AgentInfo
	for i := range infos {
		byType[infos[i].Type]++
		if infos[i].Type == "semgrep" {
			semgrep = &infos[i]
		}
	}
	if semgrep == nil {
		t.Fatalf("semgrep plugin missing from /api/agents; got %+v", infos)
	}
	if semgrep.Name != "Semgrep (bundled)" {
		t.Errorf("semgrep Name = %q, want display name", semgrep.Name)
	}
	if byType["chaos"] != 1 {
		t.Errorf("built-in chaos should appear exactly once, got %d", byType["chaos"])
	}
	if byType["disabledtool"] != 0 {
		t.Errorf("disabled plugin must not appear, got %d", byType["disabledtool"])
	}
}

// G1: registry plugins must NOT leak in read-only mode (matches existing
// built-in behaviour — empty list, no probing).
func TestAgentHandlerList_ReadOnlyHidesPlugins(t *testing.T) {
	h := NewAgentHandler(map[string]config.AgentConfig{})
	h.SetReadOnly(true)
	h.SetPluginRegistry(fakePluginReg{plugins: []pluginregistry.Plugin{mkPlugin("semgrep", "Semgrep", true)}},
		func(pluginregistry.Plugin) string { return "" })

	req := httptest.NewRequest("GET", "/api/agents", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	var infos []model.AgentInfo
	json.NewDecoder(w.Body).Decode(&infos)
	if len(infos) != 0 {
		t.Fatalf("read-only must return empty list, got %d", len(infos))
	}
}

func TestAgentHandlerList(t *testing.T) {
	// Start mock agent servers that respond to /health
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()
	unhealthySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unhealthySrv.Close()

	agents := map[string]config.AgentConfig{
		"chaos": {Name: "Chaos Engineering", Type: "chaos", URL: healthy.URL},
		"owasp": {Name: "OWASP Security", Type: "owasp", URL: unhealthySrv.URL},
	}
	h := NewAgentHandler(agents)

	req := httptest.NewRequest("GET", "/api/agents", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var infos []model.AgentInfo
	json.NewDecoder(w.Body).Decode(&infos)
	if len(infos) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(infos))
	}

	// Verify status fields are populated
	statusMap := make(map[string]string)
	for _, info := range infos {
		statusMap[info.Type] = info.Status
	}
	if statusMap["chaos"] != "healthy" {
		t.Errorf("expected chaos=healthy, got %s", statusMap["chaos"])
	}
	if statusMap["owasp"] != "unhealthy" {
		t.Errorf("expected owasp=unhealthy, got %s", statusMap["owasp"])
	}
}

func TestAgentHandlerListEmpty(t *testing.T) {
	h := NewAgentHandler(map[string]config.AgentConfig{})

	req := httptest.NewRequest("GET", "/api/agents", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var infos []model.AgentInfo
	json.NewDecoder(w.Body).Decode(&infos)
	if len(infos) != 0 {
		t.Fatalf("expected 0 agents, got %d", len(infos))
	}
}

func TestCheckAgentHealth_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	status := checkAgentHealth(srv.URL)
	if status != "healthy" {
		t.Errorf("expected healthy, got %s", status)
	}
}

func TestCheckAgentHealth_Unhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	status := checkAgentHealth(srv.URL)
	if status != "unhealthy" {
		t.Errorf("expected unhealthy, got %s", status)
	}
}

func TestCheckAgentHealth_Unreachable(t *testing.T) {
	status := checkAgentHealth("http://localhost:1")
	if status != "unhealthy" {
		t.Errorf("expected unhealthy for unreachable, got %s", status)
	}
}

func TestCheckAgentHealth_EmptyURL(t *testing.T) {
	status := checkAgentHealth("")
	if status != "unknown" {
		t.Errorf("expected unknown for empty URL, got %s", status)
	}
}
