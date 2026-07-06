package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/pkg/pluginregistry"
	"github.com/vulture/backend/pkg/stagerouter"
)

// mockAgentProxyService implements AgentProxyService for testing.
type mockAgentProxyService struct {
	runAgentFn            func(ctx context.Context, agentURL, agentType, runID, sourcePath string, cfg json.RawMessage, eventCh chan<- *model.AgUIEvent) error
	runAgentWithContextFn func(ctx context.Context, agentURL, agentType, runID, sourcePath string, cfg json.RawMessage, priorFindings []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error
}

func (m *mockAgentProxyService) RunAgent(ctx context.Context, agentURL, agentType, runID, sourcePath string, cfg json.RawMessage, eventCh chan<- *model.AgUIEvent) error {
	if m.runAgentFn != nil {
		return m.runAgentFn(ctx, agentURL, agentType, runID, sourcePath, cfg, eventCh)
	}
	return nil
}

func (m *mockAgentProxyService) RunAgentWithContext(ctx context.Context, agentURL, agentType, runID, sourcePath string, cfg json.RawMessage, priorFindings []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error {
	if m.runAgentWithContextFn != nil {
		return m.runAgentWithContextFn(ctx, agentURL, agentType, runID, sourcePath, cfg, priorFindings, eventCh)
	}
	return nil
}

func TestStreamService_Stream(t *testing.T) {
	var calledAgents []string
	proxy := &mockAgentProxyService{
		runAgentWithContextFn: func(ctx context.Context, agentURL, agentType, runID, sourcePath string, cfg json.RawMessage, prior []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error {
			calledAgents = append(calledAgents, agentType)
			return nil
		},
	}
	svc := NewStreamService(proxy)

	audit := &model.Audit{
		ID:     "audit-1",
		Types:  []string{"chaos"},
		Config: json.RawMessage(`{"chaos":{"patterns":["retry"]}}`),
	}
	agents := map[string]config.AgentConfig{
		"chaos": {URL: "http://localhost:28001"},
	}
	eventCh := make(chan *model.AgUIEvent, 100)

	svc.Stream(context.Background(), audit, "/src", agents, eventCh)

	var events []*model.AgUIEvent
	for evt := range eventCh {
		events = append(events, evt)
	}

	if len(events) < 2 {
		t.Fatalf("expected at least 2 events (start + finish), got %d", len(events))
	}
	if events[0].Type != model.EventRunStarted {
		t.Errorf("first event should be RunStarted, got %s", events[0].Type)
	}
	if events[len(events)-1].Type != model.EventRunFinished {
		t.Errorf("last event should be RunFinished, got %s", events[len(events)-1].Type)
	}
	if len(calledAgents) != 1 || calledAgents[0] != "chaos" {
		t.Errorf("expected chaos agent called, got %v", calledAgents)
	}
}

func TestStreamService_StreamWithContext(t *testing.T) {
	var gotPrior []model.PriorFinding
	proxy := &mockAgentProxyService{
		runAgentWithContextFn: func(ctx context.Context, agentURL, agentType, runID, sourcePath string, cfg json.RawMessage, prior []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error {
			gotPrior = prior
			return nil
		},
	}
	svc := NewStreamService(proxy)

	audit := &model.Audit{
		ID:     "audit-2",
		Types:  []string{"owasp"},
		Config: json.RawMessage(`{}`),
	}
	agents := map[string]config.AgentConfig{
		"owasp": {URL: "http://localhost:28002"},
	}
	priorByAgent := map[string][]model.PriorFinding{
		"owasp": {{Title: "XSS", Severity: "high"}},
	}
	eventCh := make(chan *model.AgUIEvent, 100)

	svc.StreamWithContext(context.Background(), audit, "/src", agents, priorByAgent, eventCh)

	for range eventCh {
	}

	if len(gotPrior) != 1 {
		t.Fatalf("expected 1 prior finding, got %d", len(gotPrior))
	}
	if gotPrior[0].Title != "XSS" {
		t.Errorf("expected prior title XSS, got %s", gotPrior[0].Title)
	}
}

func TestStreamService_SkipUnconfiguredAgent(t *testing.T) {
	proxy := &mockAgentProxyService{
		runAgentWithContextFn: func(ctx context.Context, agentURL, agentType, runID, sourcePath string, cfg json.RawMessage, prior []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error {
			t.Errorf("should not call unconfigured agent %s", agentType)
			return nil
		},
	}
	svc := NewStreamService(proxy)

	audit := &model.Audit{
		ID:     "audit-3",
		Types:  []string{"gdpr"},
		Config: json.RawMessage(`{}`),
	}
	agents := map[string]config.AgentConfig{
		"chaos": {URL: "http://localhost:28001"},
	}
	eventCh := make(chan *model.AgUIEvent, 100)

	svc.StreamWithContext(context.Background(), audit, "/src", agents, nil, eventCh)
	for range eventCh {
	}
}

func TestStreamService_SkipEmptyURL(t *testing.T) {
	called := false
	proxy := &mockAgentProxyService{
		runAgentWithContextFn: func(ctx context.Context, agentURL, agentType, runID, sourcePath string, cfg json.RawMessage, prior []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error {
			called = true
			return nil
		},
	}
	svc := NewStreamService(proxy)

	audit := &model.Audit{
		ID:     "audit-4",
		Types:  []string{"chaos"},
		Config: json.RawMessage(`{}`),
	}
	agents := map[string]config.AgentConfig{
		"chaos": {URL: ""},
	}
	eventCh := make(chan *model.AgUIEvent, 100)

	svc.StreamWithContext(context.Background(), audit, "/src", agents, nil, eventCh)
	for range eventCh {
	}

	if called {
		t.Error("should not call agent with empty URL")
	}
}

func TestStreamService_MultipleAgents(t *testing.T) {
	var mu sync.Mutex
	var calledAgents []string
	proxy := &mockAgentProxyService{
		runAgentWithContextFn: func(ctx context.Context, agentURL, agentType, runID, sourcePath string, cfg json.RawMessage, prior []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error {
			mu.Lock()
			calledAgents = append(calledAgents, agentType)
			mu.Unlock()
			return nil
		},
	}
	svc := NewStreamService(proxy)

	audit := &model.Audit{
		ID:     "audit-5",
		Types:  []string{"chaos", "owasp", "soc2"},
		Config: json.RawMessage(`{}`),
	}
	agents := map[string]config.AgentConfig{
		"chaos": {URL: "http://localhost:28001"},
		"owasp": {URL: "http://localhost:28002"},
		"soc2":  {URL: "http://localhost:28003"},
	}
	eventCh := make(chan *model.AgUIEvent, 100)

	// StreamWithContext blocks until all agents are done, then sends RunFinished and closes eventCh
	svc.StreamWithContext(context.Background(), audit, "/src", agents, nil, eventCh)
	for range eventCh {
	}

	mu.Lock()
	count := len(calledAgents)
	mu.Unlock()
	if count != 3 {
		t.Errorf("expected 3 agents called, got %d: %v", count, calledAgents)
	}
}

func TestStreamService_AgentError(t *testing.T) {
	proxy := &mockAgentProxyService{
		runAgentWithContextFn: func(ctx context.Context, agentURL, agentType, runID, sourcePath string, cfg json.RawMessage, prior []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error {
			return context.DeadlineExceeded
		},
	}
	svc := NewStreamService(proxy)

	audit := &model.Audit{
		ID:     "audit-err",
		Types:  []string{"chaos"},
		Config: json.RawMessage(`{}`),
	}
	agents := map[string]config.AgentConfig{
		"chaos": {URL: "http://localhost:28001"},
	}
	eventCh := make(chan *model.AgUIEvent, 100)

	// Should not panic even when agent errors
	svc.StreamWithContext(context.Background(), audit, "/src", agents, nil, eventCh)
	for range eventCh {
	}
}

// fakeRouter returns a fixed set of dispatch targets (0055 path-rewrite test).
type fakeRouter struct{ targets []stagerouter.DispatchTarget }

func (f *fakeRouter) Route(stagerouter.RouteRequest) ([]stagerouter.DispatchTarget, error) {
	return f.targets, nil
}

// TestStreamService_LocalModeContainerPathRewrite_0055 was replaced by
// feature 0058 (R11/S3): the /audit-inputs/<raw-host-path> rewrite it pinned
// rode on the host-/ mount, a security defect superseded by per-audit
// staging. The successor below pins the full 0058 P0c contract.
func TestStreamService_LocalModeContainerStaging_0058(t *testing.T) {
	t.Setenv("VULTURE_LOCAL_MODE", "true")
	auditsDir := t.TempDir()
	t.Setenv("VULTURE_SUPERVISOR_AUDITS_DIR", auditsDir)
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("write source fixture: %v", err)
	}

	var mu sync.Mutex
	gotSource := map[string]string{}
	proxy := &mockAgentProxyService{
		runAgentWithContextFn: func(ctx context.Context, agentURL, agentType, runID, sourcePath string, cfg json.RawMessage, prior []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error {
			mu.Lock()
			gotSource[agentType] = sourcePath
			mu.Unlock()
			// The staged tree must exist while agents run.
			if agentType == "semgrep" {
				if _, err := os.Stat(filepath.Join(auditsDir, runID, "main.go")); err != nil {
					t.Errorf("staged source missing during dispatch: %v", err)
				}
			}
			return nil
		},
	}
	router := &fakeRouter{targets: []stagerouter.DispatchTarget{
		{PluginName: "semgrep", URL: "http://localhost:28011", Phase: "scan", RuntimeType: pluginregistry.RuntimeContainer},
		{PluginName: "chaos", URL: "http://localhost:28001", Phase: "scan", RuntimeType: pluginregistry.RuntimeInTree},
	}}
	svc := &streamService{proxy: proxy, router: router}

	audit := &model.Audit{ID: "a1", Types: []string{"semgrep", "chaos"}, Config: json.RawMessage(`{}`)}
	eventCh := make(chan *model.AgUIEvent, 100)
	svc.Stream(context.Background(), audit, srcDir, nil, eventCh)
	for range eventCh {
	}

	mu.Lock()
	defer mu.Unlock()
	// Container plugin: dispatched the STAGED path (audit-id scoped), never
	// a host-path join (0058 R11).
	if gotSource["semgrep"] != "/audit-inputs/a1" {
		t.Errorf("semgrep source_path = %q, want /audit-inputs/a1", gotSource["semgrep"])
	}
	// In-tree (native) agent: raw host path, unchanged.
	if gotSource["chaos"] != srcDir {
		t.Errorf("chaos source_path = %q, want %q (unchanged)", gotSource["chaos"], srcDir)
	}
	// Staged tree is reaped once the audit's agents finish.
	if _, err := os.Stat(filepath.Join(auditsDir, "a1")); !os.IsNotExist(err) {
		t.Errorf("staged dir not reaped after Stream: stat err=%v", err)
	}
}
