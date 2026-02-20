package agui

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/vulture/backend/internal/model"
)

type AgentEvent struct {
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

type translatorFunc func(agentType string, data json.RawMessage) ([]*model.AgUIEvent, error)

var translators = map[string]translatorFunc{
	"agent_start":   func(at string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateAgentStart(at, d) },
	"thinking":      func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateThinking(d) },
	"tool_call":     func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateToolCall(d) },
	"tool_result":   func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateToolResult(d) },
	"finding":       func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateFinding(d) },
	"progress":      func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateProgress(d) },
	"result":        func(at string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateResult(at, d) },
	"token_savings": func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateTokenSavings(d) },
	"dedup_stats":   func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateDedupStats(d) },
	"agent_end":     func(at string, _ json.RawMessage) ([]*model.AgUIEvent, error) { return translateAgentEnd(at) },
}

func Translate(agentType string, event string, data json.RawMessage) ([]*model.AgUIEvent, error) {
	fn, ok := translators[event]
	if !ok {
		return nil, nil
	}
	return fn(agentType, data)
}

func translateAgentStart(agentType string, _ json.RawMessage) ([]*model.AgUIEvent, error) {
	return []*model.AgUIEvent{
		{Type: model.EventStepStarted, StepName: agentType, StepID: "step-" + agentType},
	}, nil
}

func translateThinking(data json.RawMessage) ([]*model.AgUIEvent, error) {
	var d struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("unmarshal thinking: %w", err)
	}
	delta, _ := json.Marshal(d.Content)
	return []*model.AgUIEvent{
		{Type: model.EventTextMessageContent, MessageID: "msg-thinking", Delta: delta},
	}, nil
}

func translateToolCall(data json.RawMessage) ([]*model.AgUIEvent, error) {
	var d struct {
		Tool string          `json:"tool"`
		Args json.RawMessage `json:"args"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("unmarshal tool_call: %w", err)
	}
	return []*model.AgUIEvent{
		{Type: model.EventToolCallStart, ToolName: d.Tool, ToolID: "tc-" + d.Tool},
		{Type: model.EventToolCallArgs, ToolID: "tc-" + d.Tool, ToolArgs: d.Args},
	}, nil
}

func translateToolResult(data json.RawMessage) ([]*model.AgUIEvent, error) {
	var d struct {
		Tool string `json:"tool"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("unmarshal tool_result: %w", err)
	}
	return []*model.AgUIEvent{
		{Type: model.EventToolCallEnd, ToolID: "tc-" + d.Tool},
	}, nil
}

func translateFinding(data json.RawMessage) ([]*model.AgUIEvent, error) {
	patch, _ := json.Marshal([]map[string]interface{}{
		{"op": "add", "path": "/findings/-", "value": json.RawMessage(data)},
	})
	return []*model.AgUIEvent{
		{Type: model.EventStateDelta, Delta: patch},
	}, nil
}

func translateProgress(data json.RawMessage) ([]*model.AgUIEvent, error) {
	return []*model.AgUIEvent{
		{Type: model.EventStateDelta, Delta: data},
	}, nil
}

func translateResult(agentType string, data json.RawMessage) ([]*model.AgUIEvent, error) {
	log.Printf("[translate] result agent=%s dataLen=%d data=%.200s", agentType, len(data), string(data))
	return []*model.AgUIEvent{
		{Type: model.EventStateSnapshot, Snapshot: data, AgentType: agentType},
	}, nil
}

func translateTokenSavings(data json.RawMessage) ([]*model.AgUIEvent, error) {
	// Wrap token savings data so the frontend can distinguish it from other state deltas
	wrapped, _ := json.Marshal(map[string]json.RawMessage{"token_savings": data})
	return []*model.AgUIEvent{
		{Type: model.EventStateDelta, Delta: wrapped},
	}, nil
}

func translateDedupStats(data json.RawMessage) ([]*model.AgUIEvent, error) {
	wrapped, _ := json.Marshal(map[string]json.RawMessage{"dedup_stats": data})
	return []*model.AgUIEvent{
		{Type: model.EventStateDelta, Delta: wrapped},
	}, nil
}

func translateAgentEnd(agentType string) ([]*model.AgUIEvent, error) {
	return []*model.AgUIEvent{
		{Type: model.EventStepFinished, StepName: agentType, StepID: "step-" + agentType},
	}, nil
}
