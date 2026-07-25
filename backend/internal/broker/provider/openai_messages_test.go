package provider

import (
	"encoding/json"
	"testing"
)

// §32.1 #9c (outbound counterpart of #9b): on a multi-turn tool loop the broker
// relays the assistant turn to an OpenAI-compatible provider (LM Studio, vLLM,
// nvapi, first-party OpenAI). The OpenAI wire requires a tool call's
// name+arguments NESTED under "function"; emitting them flat makes the provider
// mishandle/ignore the replayed tool calls. buildChatBody must emit nested.
func TestBuildChatBody_AssistantToolCallsNested(t *testing.T) {
	req := CompletionRequest{
		Model: "gpt-4o",
		Messages: []Message{
			{Role: "user", Content: "scan"},
			{Role: "assistant", ToolCalls: []ToolCall{
				{ID: "c1", Type: "function", Name: "check_injection", Arguments: `{"source_path":"."}`},
			}},
			{Role: "tool", ToolCallID: "c1", Name: "check_injection", Content: "no findings"},
		},
	}
	b, _ := json.Marshal(buildChatBody(req))
	var body struct {
		Messages []struct {
			Role      string `json:"role"`
			Content   any    `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function *struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
				// a FLAT name would land here (must stay empty)
				Name string `json:"name"`
			} `json:"tool_calls"`
			ToolCallID string `json:"tool_call_id"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	// assistant turn: nested function, no flat name
	asst := body.Messages[1]
	if len(asst.ToolCalls) != 1 {
		t.Fatalf("assistant tool_calls missing: %s", b)
	}
	tc := asst.ToolCalls[0]
	if tc.Function == nil || tc.Function.Name != "check_injection" || tc.Function.Arguments != `{"source_path":"."}` {
		t.Errorf("tool call not nested under function: %s", b)
	}
	if tc.Name != "" {
		t.Errorf("tool call must NOT carry a flat top-level name: %s", b)
	}
	if tc.ID != "c1" || tc.Type != "function" {
		t.Errorf("tool call id/type lost: %+v", tc)
	}
	// tool result: role tool + tool_call_id preserved
	toolMsg := body.Messages[2]
	if toolMsg.Role != "tool" || toolMsg.ToolCallID != "c1" {
		t.Errorf("tool result message shape wrong: %+v", toolMsg)
	}
}

// A plain user/system conversation must pass through unchanged.
func TestBuildChatBody_PlainMessagesUnchanged(t *testing.T) {
	req := CompletionRequest{
		Model:    "gpt-4o",
		Messages: []Message{{Role: "system", Content: "sys"}, {Role: "user", Content: "hi"}},
	}
	b, _ := json.Marshal(buildChatBody(req))
	var body struct {
		Messages []map[string]any `json:"messages"`
	}
	_ = json.Unmarshal(b, &body)
	if len(body.Messages) != 2 || body.Messages[0]["content"] != "sys" || body.Messages[1]["content"] != "hi" {
		t.Errorf("plain messages altered: %s", b)
	}
}
