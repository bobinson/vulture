package agui

import (
	"encoding/json"
	"testing"

	"github.com/vulture/backend/internal/model"
)

func TestTranslateAgentStart(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"agent_name": "Test", "run_id": "r-1"})
	events, err := Translate("chaos", "agent_start", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != model.EventStepStarted {
		t.Fatalf("expected StepStarted, got %s", events[0].Type)
	}
	if events[0].StepName != "chaos" {
		t.Fatalf("expected step name chaos, got %s", events[0].StepName)
	}
}

func TestTranslateThinking(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"content": "Analyzing..."})
	events, err := Translate("chaos", "thinking", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != model.EventTextMessageContent {
		t.Fatalf("expected TextMessageContent, got %s", events[0].Type)
	}
}

func TestTranslateToolCall(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"tool": "list_files", "args": map[string]string{"path": "/tmp"}})
	events, err := Translate("chaos", "tool_call", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Type != model.EventToolCallStart {
		t.Fatalf("expected ToolCallStart, got %s", events[0].Type)
	}
	if events[1].Type != model.EventToolCallArgs {
		t.Fatalf("expected ToolCallArgs, got %s", events[1].Type)
	}
}

func TestTranslateToolResult(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"tool": "list_files", "result": []string{"a.go"}})
	events, err := Translate("chaos", "tool_result", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 || events[0].Type != model.EventToolCallEnd {
		t.Fatalf("expected ToolCallEnd event")
	}
}

func TestTranslateFinding(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"severity": "high", "title": "Test"})
	events, err := Translate("chaos", "finding", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 || events[0].Type != model.EventStateDelta {
		t.Fatalf("expected StateDelta event")
	}
}

func TestTranslateResult(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"score": 85})
	events, err := Translate("chaos", "result", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 || events[0].Type != model.EventStateSnapshot {
		t.Fatalf("expected StateSnapshot event")
	}
}

func TestTranslateAgentEnd(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"run_id": "r-1", "status": "completed"})
	events, err := Translate("chaos", "agent_end", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 || events[0].Type != model.EventStepFinished {
		t.Fatalf("expected StepFinished event")
	}
}

func TestTranslateProgress(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"files_analyzed": 5})
	events, err := Translate("chaos", "progress", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 || events[0].Type != model.EventStateDelta {
		t.Fatalf("expected StateDelta event")
	}
}

func TestTranslateTokenSavings(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{
		"context_tokens":      50,
		"raw_tokens":          150,
		"tokens_saved":        100,
		"savings_pct":         67,
		"prior_findings_used": 5,
		"duplicates_removed":  10,
	})
	events, err := Translate("owasp", "token_savings", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 || events[0].Type != model.EventStateDelta {
		t.Fatalf("expected StateDelta event for token_savings")
	}
	// Verify the delta wraps the data under "token_savings" key
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(events[0].Delta, &wrapper); err != nil {
		t.Fatalf("unmarshal delta: %v", err)
	}
	if _, ok := wrapper["token_savings"]; !ok {
		t.Fatalf("expected token_savings key in delta")
	}
}

func TestTranslateUnknown(t *testing.T) {
	events, err := Translate("chaos", "unknown_event", json.RawMessage("{}"))
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if events != nil {
		t.Fatalf("expected nil events for unknown, got %d", len(events))
	}
}
