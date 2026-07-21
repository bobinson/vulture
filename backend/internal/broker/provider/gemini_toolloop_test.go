package provider

import (
	"encoding/json"
	"testing"
)

// helper: build the request and decode the tools/contents we assert on.
func buildGem(t *testing.T, req CompletionRequest) gemRequest {
	t.Helper()
	return buildGeminiRequest(req)
}

// §32.1 #9: a tool-result message carries tool_call_id (name empty in the
// OpenAI wire). Gemini requires functionResponse.name to match the prior
// functionCall.name — so the adapter must resolve the name from the assistant
// turn's tool_calls, not copy the empty m.Name.
func TestGemini_ToolResultNameResolvedFromID(t *testing.T) {
	req := CompletionRequest{
		Model: "gemini-2.5-flash",
		Messages: []Message{
			{Role: "user", Content: "scan"},
			{Role: "assistant", ToolCalls: []ToolCall{{ID: "call_1", Name: "read_file", Arguments: `{"path":"a.go"}`}}},
			{Role: "tool", ToolCallID: "call_1", Content: "file contents"},
		},
	}
	out := buildGem(t, req)
	// last content = the tool result; its functionResponse.name must be resolved.
	last := out.Contents[len(out.Contents)-1]
	if last.Role != "user" || len(last.Parts) != 1 || last.Parts[0].FunctionResponse == nil {
		t.Fatalf("tool result not a functionResponse user turn: %+v", last)
	}
	if got := last.Parts[0].FunctionResponse.Name; got != "read_file" {
		t.Errorf("functionResponse.name = %q, want read_file (resolved from call_1)", got)
	}
}

// §32.1 #10: parallel tool calls yield multiple tool-result messages that must
// be COALESCED into a single user turn (multiple functionResponse parts) —
// consecutive same-role user turns break Gemini's turn alternation.
func TestGemini_ParallelToolResultsCoalesced(t *testing.T) {
	req := CompletionRequest{
		Model: "gemini-2.5-flash",
		Messages: []Message{
			{Role: "user", Content: "scan"},
			{Role: "assistant", ToolCalls: []ToolCall{
				{ID: "c1", Name: "read_file"},
				{ID: "c2", Name: "list_files"},
			}},
			{Role: "tool", ToolCallID: "c1", Content: "r1"},
			{Role: "tool", ToolCallID: "c2", Content: "r2"},
		},
	}
	out := buildGem(t, req)
	// count user turns whose parts are all functionResponse
	toolTurns, totalParts := 0, 0
	for _, c := range out.Contents {
		if c.Role == "user" && len(c.Parts) > 0 && c.Parts[0].FunctionResponse != nil {
			toolTurns++
			totalParts += len(c.Parts)
		}
	}
	if toolTurns != 1 {
		t.Errorf("parallel tool results must coalesce into 1 user turn, got %d", toolTurns)
	}
	if totalParts != 2 {
		t.Errorf("coalesced turn must hold both functionResponse parts, got %d", totalParts)
	}
	names := map[string]bool{}
	for _, c := range out.Contents {
		for _, p := range c.Parts {
			if p.FunctionResponse != nil {
				names[p.FunctionResponse.Name] = true
			}
		}
	}
	if !names["read_file"] || !names["list_files"] {
		t.Errorf("both resolved names must be present: %v", names)
	}
}

// §32.1 #11: Gemini may emit a functionCall with absent/empty args; the parsed
// ToolCall.Arguments must be valid JSON ("{}"), not "" or "null", or the SDK's
// json.loads fails / returns None.
func TestGemini_EmptyFunctionCallArgsNormalized(t *testing.T) {
	for _, raw := range []string{``, `null`, `   `} {
		wire := &gemResponse{}
		wire.UsageMetadata = &struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
		}{PromptTokenCount: 1, CandidatesTokenCount: 1}
		wire.Candidates = []struct {
			Content struct {
				Parts []struct {
					Text         string `json:"text"`
					FunctionCall *struct {
						Name string          `json:"name"`
						Args json.RawMessage `json:"args"`
					} `json:"functionCall"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		}{{}}
		wire.Candidates[0].Content.Parts = make([]struct {
			Text         string `json:"text"`
			FunctionCall *struct {
				Name string          `json:"name"`
				Args json.RawMessage `json:"args"`
			} `json:"functionCall"`
		}, 1)
		wire.Candidates[0].Content.Parts[0].FunctionCall = &struct {
			Name string          `json:"name"`
			Args json.RawMessage `json:"args"`
		}{Name: "no_args_tool", Args: json.RawMessage(raw)}

		a := &geminiAdapter{name: "gemini"}
		resp, err := a.toResponse(wire, "gemini-2.5-flash", "r")
		if err != nil {
			t.Fatalf("toResponse: %v", err)
		}
		if len(resp.ToolCalls) != 1 {
			t.Fatalf("want 1 tool call, got %d", len(resp.ToolCalls))
		}
		if got := resp.ToolCalls[0].Arguments; got != "{}" {
			t.Errorf("empty args %q normalized to %q, want {}", raw, got)
		}
	}
}
