package service

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/pkg/pluginregistry"
	"github.com/vulture/backend/pkg/stagerouter"
)

// recordCalls is a mutex-guarded helper used by the router-path
// tests below, which fan out multiple goroutines through the stream
// service and append from each.
type recordCalls struct {
	mu     sync.Mutex
	agents []string
}

func (r *recordCalls) add(a string) {
	r.mu.Lock()
	r.agents = append(r.agents, a)
	r.mu.Unlock()
}

func (r *recordCalls) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.agents))
	copy(out, r.agents)
	return out
}

// fakeRegistry is a minimal pluginregistry.Registry for service-level
// tests. Mirrors the one in pkg/stagerouter/router_test.go but lives
// here to keep that test package internal-only.
type fakeRegistry struct{ plugins []pluginregistry.Plugin }

func (f *fakeRegistry) All() []pluginregistry.Plugin { return f.plugins }
func (f *fakeRegistry) Enabled() []pluginregistry.Plugin {
	out := make([]pluginregistry.Plugin, 0, len(f.plugins))
	for _, p := range f.plugins {
		if p.Enabled {
			out = append(out, p)
		}
	}
	return out
}
func (f *fakeRegistry) ByName(name string) (pluginregistry.Plugin, bool) {
	for _, p := range f.plugins {
		if p.Name() == name {
			return p, true
		}
	}
	return pluginregistry.Plugin{}, false
}

func mkScanPlugin(name string) pluginregistry.Plugin {
	return pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{
				Name: name, Version: "1.0.0", APIVersion: pluginregistry.APIVersionV1,
				Publisher: "x", Description: "y",
			},
			Trust:   pluginregistry.TrustBlock{Tier: pluginregistry.TierInTree},
			Runtime: pluginregistry.RuntimeBlock{Type: pluginregistry.RuntimeInTree, ModulePath: name + ".main:app"},
			Capabilities: []pluginregistry.Capability{
				{Phase: "scan", Emits: []string{"finding", "result"}},
			},
		},
		Source: "in-tree", Enabled: true,
	}
}

// TestStreamService_LegacyDispatchWhenNoRouter confirms the
// nil-router constructor still uses audit.Types iteration as a
// fallback. This is the path that fires when the registry didn't
// build (degraded mode) or when tests construct via NewStreamService.
// (Replaces the prior VULTURE_STAGE_ROUTER flag test; the flag was
// removed once the router shipped cleanly through 0050-0053.)
func TestStreamService_LegacyDispatchWhenNoRouter(t *testing.T) {
	rec := &recordCalls{}
	proxy := &mockAgentProxyService{
		runAgentWithContextFn: func(ctx context.Context, url, agentType, runID, sp string, cfg json.RawMessage, prior []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error {
			rec.add(agentType)
			return nil
		},
	}
	// NewStreamService — no router wired. Legacy audit.Types path.
	svc := NewStreamService(proxy)
	agents := map[string]config.AgentConfig{
		"owasp": {URL: "http://owasp"}, "chaos": {URL: "http://chaos"},
	}

	audit := &model.Audit{ID: "a-norouter", Types: []string{"owasp"}, Config: json.RawMessage(`{}`)}
	eventCh := make(chan *model.AgUIEvent, 16)
	svc.Stream(context.Background(), audit, "/src", agents, eventCh)
	for range eventCh {
	}

	// Legacy path follows audit.Types exactly → only "owasp".
	called := rec.snapshot()
	if len(called) != 1 || called[0] != "owasp" {
		t.Errorf("legacy path: expected only owasp, got %v", called)
	}
}

// TestStreamService_RouterDispatchUsesRegistry verifies that when a
// router is wired, registered plugins matching the requested types
// fire via the router, not via cfg.Agents iteration of audit.Types.
func TestStreamService_RouterDispatchUsesRegistry(t *testing.T) {
	rec := &recordCalls{}
	proxy := &mockAgentProxyService{
		runAgentWithContextFn: func(ctx context.Context, url, agentType, runID, sp string, cfg json.RawMessage, prior []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error {
			rec.add(agentType)
			return nil
		},
	}
	registry := &fakeRegistry{plugins: []pluginregistry.Plugin{
		mkScanPlugin("owasp"), mkScanPlugin("chaos"), mkScanPlugin("cwe"),
	}}
	agents := map[string]config.AgentConfig{
		"owasp": {URL: "http://owasp"}, "chaos": {URL: "http://chaos"}, "cwe": {URL: "http://cwe"},
	}
	router := stagerouter.New(registry, agents)
	svc := NewStreamServiceWithRouter(proxy, router)

	// audit.Types acts as an allow-list; only owasp + cwe should
	// fire even though chaos is registered + has a URL.
	audit := &model.Audit{ID: "a-router", Types: []string{"owasp", "cwe"}, Config: json.RawMessage(`{}`)}
	eventCh := make(chan *model.AgUIEvent, 16)
	svc.Stream(context.Background(), audit, "/src", agents, eventCh)
	for range eventCh {
	}

	called := rec.snapshot()
	sort.Strings(called)
	if len(called) != 2 || called[0] != "cwe" || called[1] != "owasp" {
		t.Errorf("router path: expected [cwe owasp], got %v", called)
	}
}

// TestStreamService_RouterDedupsMultiCapability proves that a plugin
// returning multiple DispatchTargets (one per matched capability)
// gets called exactly once per audit. Review MAJOR #9 dedup policy.
func TestStreamService_RouterDedupsMultiCapability(t *testing.T) {
	rec := &recordCalls{}
	proxy := &mockAgentProxyService{
		runAgentWithContextFn: func(ctx context.Context, url, agentType, runID, sp string, cfg json.RawMessage, prior []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error {
			rec.add(agentType)
			return nil
		},
	}
	// Plugin "multi" with 2 scan capabilities → router returns 2
	// DispatchTargets → service must dedupe to 1 launch.
	plug := mkScanPlugin("multi")
	plug.Manifest.Capabilities = []pluginregistry.Capability{
		{Phase: "scan", Emits: []string{"finding"}},
		{Phase: "scan", Emits: []string{"finding"}, Languages: []string{"python"}},
	}
	registry := &fakeRegistry{plugins: []pluginregistry.Plugin{plug}}
	agents := map[string]config.AgentConfig{"multi": {URL: "http://multi"}}
	router := stagerouter.New(registry, agents)
	svc := NewStreamServiceWithRouter(proxy, router)

	audit := &model.Audit{ID: "a-dedup", Types: nil, Config: json.RawMessage(`{}`)}
	eventCh := make(chan *model.AgUIEvent, 16)
	svc.Stream(context.Background(), audit, "/src", agents, eventCh)
	for range eventCh {
	}
	called := rec.snapshot()
	if len(called) != 1 {
		t.Errorf("multi-capability plugin should be launched once, got %d calls (%v)", len(called), called)
	}
}
