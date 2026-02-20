package service

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
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
		"chaos": {URL: "http://localhost:8001"},
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
		"owasp": {URL: "http://localhost:8002"},
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
		"chaos": {URL: "http://localhost:8001"},
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
		"chaos": {URL: "http://localhost:8001"},
		"owasp": {URL: "http://localhost:8002"},
		"soc2":  {URL: "http://localhost:8003"},
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
		"chaos": {URL: "http://localhost:8001"},
	}
	eventCh := make(chan *model.AgUIEvent, 100)

	// Should not panic even when agent errors
	svc.StreamWithContext(context.Background(), audit, "/src", agents, nil, eventCh)
	for range eventCh {
	}
}

func TestExtractAgentConfig_WithMatchingKey(t *testing.T) {
	fullConfig := json.RawMessage(`{"owasp":{"rules":["A1","A2"]},"chaos":{"patterns":["retry"]}}`)
	result := extractAgentConfig(fullConfig, "owasp")

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	rules, ok := parsed["rules"]
	if !ok {
		t.Fatal("expected 'rules' key in extracted config")
	}
	arr, ok := rules.([]interface{})
	if !ok || len(arr) != 2 {
		t.Errorf("expected 2 rules, got %v", rules)
	}
}

func TestExtractAgentConfig_WithoutMatchingKey(t *testing.T) {
	fullConfig := json.RawMessage(`{"owasp":{"rules":["A1"]}}`)
	result := extractAgentConfig(fullConfig, "soc2")

	if string(result) != "{}" {
		t.Errorf("expected empty config, got %s", string(result))
	}
}

func TestExtractAgentConfig_InvalidJSON(t *testing.T) {
	fullConfig := json.RawMessage(`not valid json`)
	result := extractAgentConfig(fullConfig, "owasp")

	if string(result) != "{}" {
		t.Errorf("expected empty config for invalid JSON, got %s", string(result))
	}
}

func TestExtractAgentConfig_EmptyConfig(t *testing.T) {
	fullConfig := json.RawMessage(`{}`)
	result := extractAgentConfig(fullConfig, "owasp")

	if string(result) != "{}" {
		t.Errorf("expected empty config, got %s", string(result))
	}
}

func TestExtractAgentConfig_NullConfig(t *testing.T) {
	fullConfig := json.RawMessage(`null`)
	result := extractAgentConfig(fullConfig, "owasp")

	if string(result) != "{}" {
		t.Errorf("expected empty config for null, got %s", string(result))
	}
}
