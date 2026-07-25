package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/pkg/pluginregistry"
	"github.com/vulture/backend/pkg/stagerouter"
)

// TestStreamService_RouterEndToEndWithSyntheticPlugin closes the
// last open acceptance criterion of feature 0049 (#8 from the plan):
// an externally-registered plugin reachable only via the stage
// router actually delivers a finding through the SSE stream into
// the audit's findings list.
//
// Wiring:
//
//	[fake registry]
//	   └─ "syn-scan" (user-supplied tier, container runtime)
//	         routes to ↓
//	[stagerouter] resolves URL via cfg.Agents map
//	         ↓
//	[real stream service with router]
//	         ↓
//	[real agent_proxy_service] POSTs /run, reads SSE
//	         ↓
//	[httptest server] emits one `finding` event + one `result`
//
// The test asserts that the finding propagates through the event
// channel as a StateDelta whose embedded JSON Patch adds a finding
// row with the synthetic title.
func TestStreamService_RouterEndToEndWithSyntheticPlugin(t *testing.T) {
	// Synthetic plugin: HTTP server that emits an SSE stream when
	// the proxy POSTs /run. One `finding`, one `result`.
	const finding = `{"id":"syn-1","title":"Synthetic SQL Injection","severity":"high","category":"CWE-89","file_path":"app/db.py","line_start":42,"line_end":42}`
	const result = `{"findings":[{"id":"syn-1","title":"Synthetic SQL Injection","severity":"high","category":"CWE-89"}],"score":50}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/run" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		writeEvent := func(name, data string) {
			w.Write([]byte("event: " + name + "\n"))
			w.Write([]byte("data: " + data + "\n\n"))
			if flusher != nil {
				flusher.Flush()
			}
		}
		writeEvent("agent_start", `{"agent":"syn-scan"}`)
		writeEvent("finding", finding)
		writeEvent("result", result)
		writeEvent("agent_end", `{}`)
	}))
	defer server.Close()

	// Registry with one user-supplied scan plugin reachable via the
	// proxy. cfg.Agents holds the URL — same path operators use to
	// override container-network defaults.
	plug := pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{
				Name: "syn-scan", Version: "0.1.0",
				APIVersion: pluginregistry.APIVersionV1,
				Publisher:  "tests", Description: "synthetic",
			},
			Trust: pluginregistry.TrustBlock{
				Tier:        pluginregistry.TierUserSupplied,
				RequiredAck: []string{"network-egress"},
			},
			Runtime: pluginregistry.RuntimeBlock{
				Type: pluginregistry.RuntimeContainer, Image: "x:1", Port: 28100,
			},
			Capabilities: []pluginregistry.Capability{{
				Phase: "scan", Emits: []string{"finding", "result"},
			}},
		},
		Source: "env:test", Enabled: true,
	}
	registry := &fakeRegistry{plugins: []pluginregistry.Plugin{plug}}
	agents := map[string]config.AgentConfig{
		"syn-scan": {URL: server.URL, Name: "syn-scan", Type: "syn-scan"},
	}

	proxy := NewAgentProxyService()
	router := stagerouter.New(registry, agents)
	svc := NewStreamServiceWithRouter(proxy, router)

	audit := &model.Audit{
		ID:     "audit-syn",
		Types:  []string{"syn-scan"},
		Config: json.RawMessage(`{}`),
	}

	eventCh := make(chan *model.AgUIEvent, 64)
	svc.Stream(context.Background(), audit, "/tmp/fake-src", agents, eventCh)

	var (
		sawRunStarted     bool
		sawRunFinished    bool
		sawFindingDelta   bool
		sawResultSnapshot bool
	)
	for evt := range eventCh {
		switch evt.Type {
		case model.EventRunStarted:
			sawRunStarted = true
		case model.EventRunFinished:
			sawRunFinished = true
		case model.EventStateDelta:
			if strings.Contains(string(evt.Delta), "Synthetic SQL Injection") {
				sawFindingDelta = true
			}
		case model.EventStateSnapshot:
			if strings.Contains(string(evt.Snapshot), "Synthetic SQL Injection") {
				sawResultSnapshot = true
			}
		}
	}

	if !sawRunStarted {
		t.Error("missing RunStarted")
	}
	if !sawRunFinished {
		t.Error("missing RunFinished")
	}
	if !sawFindingDelta {
		t.Error("missing finding StateDelta containing synthetic title")
	}
	if !sawResultSnapshot {
		t.Error("missing result StateSnapshot containing synthetic title")
	}
}

// TestStreamService_RouterRoutesOnlyPluginsInTypes confirms the
// router's allow-list behaviour at the full-stack integration level:
// when audit.Types omits the registered plugin, the synthetic
// server is never called.
func TestStreamService_RouterRoutesOnlyPluginsInTypes(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	plug := pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin:       pluginregistry.PluginBlock{Name: "syn-other", Version: "0.1.0", APIVersion: pluginregistry.APIVersionV1, Publisher: "tests", Description: "x"},
			Trust:        pluginregistry.TrustBlock{Tier: pluginregistry.TierUserSupplied, RequiredAck: []string{"network-egress"}},
			Runtime:      pluginregistry.RuntimeBlock{Type: pluginregistry.RuntimeContainer, Image: "x:1", Port: 28101},
			Capabilities: []pluginregistry.Capability{{Phase: "scan", Emits: []string{"finding"}}},
		},
		Source: "env:test", Enabled: true,
	}
	registry := &fakeRegistry{plugins: []pluginregistry.Plugin{plug}}
	agents := map[string]config.AgentConfig{"syn-other": {URL: server.URL, Name: "syn-other", Type: "syn-other"}}

	svc := NewStreamServiceWithRouter(NewAgentProxyService(), stagerouter.New(registry, agents))

	audit := &model.Audit{
		ID:     "audit-mismatch",
		Types:  []string{"not-installed"},
		Config: json.RawMessage(`{}`),
	}
	eventCh := make(chan *model.AgUIEvent, 16)
	svc.Stream(context.Background(), audit, "/tmp/fake-src", agents, eventCh)
	for range eventCh {
	}

	if called {
		t.Error("plugin server should not have been called when its name is not in audit.Types")
	}
}
