package service

// Feature 0058 T7 — graceful notice when the Semgrep tier is unavailable
// (LLD R9 / P1c: "plugin down → CWE scan runs skills+signatures + a
// 'Semgrep tier not active' notice, exit 0").
//
// Pinned contract:
//
//   1. When a router-dispatched agent's proxy call FAILS, the stream
//      service emits an *model.AgUIEvent on eventCh with
//      Type == "thinking" whose payload/message contains the agent
//      type ("semgrep") and the phrase "not active" (case-insensitive
//      contains on the marshaled event).
//   2. The audit does NOT fail: the other agents' events still flow,
//      no RunError is emitted, and the stream still ends RunFinished.
//   3. Helper API (GREEN implements, package service):
//         func agentUnavailableEvent(agentType string) *model.AgUIEvent
//      returning the notice event described in (1).
//
// Mocks reuse mockAgentProxyService + fakeRouter from
// stream_service_test.go (same package).

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/pkg/pluginregistry"
	"github.com/vulture/backend/pkg/stagerouter"
)

// eventMentions reports whether the marshaled event contains every
// substring (case-insensitive).
func eventMentions(evt *model.AgUIEvent, subs ...string) bool {
	raw, err := json.Marshal(evt)
	if err != nil {
		return false
	}
	blob := strings.ToLower(string(raw))
	for _, sub := range subs {
		if !strings.Contains(blob, strings.ToLower(sub)) {
			return false
		}
	}
	return true
}

func collectEvents(eventCh chan *model.AgUIEvent) []*model.AgUIEvent {
	var events []*model.AgUIEvent
	for evt := range eventCh {
		events = append(events, evt)
	}
	return events
}

// gracefulTestRig runs a router-dispatched audit where the "semgrep"
// proxy call fails and the "cwe" proxy call succeeds, emitting one
// finding-ish event so we can verify other agents' events still flow.
func gracefulTestRig(t *testing.T) []*model.AgUIEvent {
	t.Helper()
	proxy := &mockAgentProxyService{
		runAgentWithContextFn: func(ctx context.Context, agentURL, agentType, runID, sourcePath string, cfg json.RawMessage, prior []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error {
			if agentType == "semgrep" {
				return errors.New("dial tcp 127.0.0.1:28011: connect: connection refused")
			}
			eventCh <- &model.AgUIEvent{
				Type:      model.EventStepStarted,
				StepName:  "CWE",
				StepID:    "step-cwe",
				AgentType: "cwe",
			}
			return nil
		},
	}
	router := &fakeRouter{targets: []stagerouter.DispatchTarget{
		{PluginName: "cwe", URL: "http://localhost:28004", Phase: "scan", RuntimeType: pluginregistry.RuntimeInTree},
		{PluginName: "semgrep", URL: "http://localhost:28011", Phase: "scan", RuntimeType: pluginregistry.RuntimeInTree},
	}}
	svc := NewStreamServiceWithRouter(proxy, router)

	audit := &model.Audit{
		ID:     "audit-0058-graceful",
		Types:  []string{"cwe", "semgrep"},
		Config: json.RawMessage(`{}`),
	}
	eventCh := make(chan *model.AgUIEvent, 100)
	svc.Stream(context.Background(), audit, "/src", nil, eventCh)
	return collectEvents(eventCh)
}

func TestStreamService_UnavailableAgent_EmitsThinkingNotice(t *testing.T) {
	events := gracefulTestRig(t)

	for _, evt := range events {
		if evt.Type == model.AgUIEventType("thinking") && eventMentions(evt, "semgrep", "not active") {
			return // contract satisfied
		}
	}
	t.Errorf(`expected a "thinking" AgUIEvent mentioning "semgrep" and "not active" when the semgrep proxy call fails; got %d events, none matched`, len(events))
}

func TestStreamService_UnavailableAgent_OtherAgentsStillFlow(t *testing.T) {
	events := gracefulTestRig(t)

	found := false
	for _, evt := range events {
		if evt.Type == model.EventStepStarted && evt.AgentType == "cwe" {
			found = true
		}
	}
	if !found {
		t.Error("cwe agent's events must still flow when semgrep is unavailable")
	}
}

func TestStreamService_UnavailableAgent_AuditDoesNotFail(t *testing.T) {
	events := gracefulTestRig(t)

	if len(events) == 0 {
		t.Fatal("expected events, got none")
	}
	for _, evt := range events {
		if evt.Type == model.EventRunError {
			t.Errorf("no RunError may be emitted for a missing augmentation tier (R9); got %+v", evt)
		}
	}
	if last := events[len(events)-1]; last.Type != model.EventRunFinished {
		t.Errorf("stream must still end with RunFinished, got %s", last.Type)
	}
}

func TestAgentUnavailableEvent_Shape(t *testing.T) {
	evt := agentUnavailableEvent("semgrep")
	if evt == nil {
		t.Fatal("agentUnavailableEvent must return a non-nil event")
	}
	if evt.Type != model.AgUIEventType("thinking") {
		t.Errorf(`agentUnavailableEvent Type = %q, want "thinking"`, evt.Type)
	}
	if !eventMentions(evt, "semgrep", "not active") {
		raw, _ := json.Marshal(evt)
		t.Errorf(`agentUnavailableEvent("semgrep") must mention "semgrep" and "not active"; got %s`, raw)
	}
}
