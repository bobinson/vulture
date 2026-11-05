package provider

import (
	"encoding/json"
	"strings"
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
						ID   string          `json:"id"`
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
				ID   string          `json:"id"`
				Name string          `json:"name"`
				Args json.RawMessage `json:"args"`
			} `json:"functionCall"`
		}, 1)
		wire.Candidates[0].Content.Parts[0].FunctionCall = &struct {
			ID   string          `json:"id"`
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

// gemWire decodes a generateContent reply the way Complete does, so the
// tool-call id tests below drive toResponse with real wire JSON.
func gemWire(t *testing.T, body string) *gemResponse {
	t.Helper()
	var w gemResponse
	if err := json.Unmarshal([]byte(body), &w); err != nil {
		t.Fatalf("decode gemini wire: %v", err)
	}
	return &w
}

func gemToolCalls(t *testing.T, a *geminiAdapter, body string) []ToolCall {
	t.Helper()
	resp, err := a.toResponse(gemWire(t, body), "gemini-2.5-flash", "req-same")
	if err != nil {
		t.Fatalf("toResponse: %v", err)
	}
	return resp.ToolCalls
}

// assertMintedID checks the OpenAI-style shape of a broker-minted id.
func assertMintedID(t *testing.T, id string) {
	t.Helper()
	if !strings.HasPrefix(id, "call_") || len(id) > 40 {
		t.Errorf("minted tool call id %q: want a call_ prefix and <= 40 chars", id)
	}
}

const gemOneCall = `{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"read_file","args":{"path":"a.go"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2}}`

// The agent SDK rejects a tool call id that an EARLIER turn already completed
// ("Model reused a completed tool call ID for a different invocation"). Each
// turn is a separate toResponse — possibly on a different adapter instance
// after a broker restart, and under the same request id — so the minted ids
// must be unique across responses, not merely within one.
func TestGemini_ToolCallIDsUniqueAcrossResponses(t *testing.T) {
	first := gemToolCalls(t, &geminiAdapter{name: "gemini"}, gemOneCall)
	second := gemToolCalls(t, &geminiAdapter{name: "gemini"}, gemOneCall)
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("want one tool call per response, got %d and %d", len(first), len(second))
	}
	assertMintedID(t, first[0].ID)
	assertMintedID(t, second[0].ID)
	if first[0].ID == second[0].ID {
		t.Errorf("two turns both got tool call id %q; ids must be unique across the run", first[0].ID)
	}
}

// Parallel calls in one response get distinct ids, and none collides with the
// ids of an identical later response.
func TestGemini_ParallelToolCallIDsDistinct(t *testing.T) {
	body := `{"candidates":[{"content":{"role":"model","parts":[
		{"functionCall":{"name":"read_file","args":{"path":"a.go"}}},
		{"text":"and"},
		{"functionCall":{"name":"read_file","args":{"path":"b.go"}}},
		{"functionCall":{"name":"grep_code","args":{"path":"exec"}}}]},"finishReason":"STOP"}],
		"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":6}}`
	a := &geminiAdapter{name: "gemini"}
	ids := map[string]bool{}
	for turn := 0; turn < 2; turn++ {
		calls := gemToolCalls(t, a, body)
		if len(calls) != 3 {
			t.Fatalf("turn %d: want 3 parallel tool calls, got %d", turn, len(calls))
		}
		for _, tc := range calls {
			assertMintedID(t, tc.ID)
			if ids[tc.ID] {
				t.Errorf("turn %d: tool call id %q issued twice", turn, tc.ID)
			}
			ids[tc.ID] = true
		}
	}
}

// When Gemini supplies functionCall.id the broker passes it through as the
// tool call id, and echoes it on the replayed functionCall and on the matching
// functionResponse so Gemini can pair them itself.
func TestGemini_SuppliedFunctionCallIDPreferredAndEchoed(t *testing.T) {
	body := `{"candidates":[{"content":{"role":"model","parts":[
		{"functionCall":{"id":"gem-fc-7f3a","name":"read_file","args":{"path":"a.go"}}},
		{"functionCall":{"name":"grep_code","args":{"path":"exec"}}}]},"finishReason":"STOP"}],
		"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":4}}`
	calls := gemToolCalls(t, &geminiAdapter{name: "gemini"}, body)
	if len(calls) != 2 {
		t.Fatalf("want 2 tool calls, got %d", len(calls))
	}
	if calls[0].ID != "gem-fc-7f3a" {
		t.Errorf("Gemini-supplied id not preferred: got %q, want gem-fc-7f3a", calls[0].ID)
	}
	if calls[1].ID == "" || calls[1].ID == calls[0].ID {
		t.Errorf("call without a Gemini id must get its own minted id, got %q", calls[1].ID)
	}

	raw, err := json.Marshal(buildGeminiRequest(CompletionRequest{
		Model: "gemini-2.5-flash",
		Messages: []Message{
			{Role: "user", Content: "scan"},
			{Role: "assistant", ToolCalls: []ToolCall{{ID: "gem-fc-7f3a", Name: "read_file", Arguments: `{"path":"a.go"}`}}},
			{Role: "tool", ToolCallID: "gem-fc-7f3a", Content: "package a"},
		},
	}))
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var wire struct {
		Contents []struct {
			Parts []struct {
				FunctionCall     map[string]any `json:"functionCall"`
				FunctionResponse map[string]any `json:"functionResponse"`
			} `json:"parts"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	var callID, respID any
	for _, c := range wire.Contents {
		for _, p := range c.Parts {
			if p.FunctionCall != nil {
				callID = p.FunctionCall["id"]
			}
			if p.FunctionResponse != nil {
				respID = p.FunctionResponse["id"]
			}
		}
	}
	if callID != "gem-fc-7f3a" || respID != "gem-fc-7f3a" {
		t.Errorf("Gemini id not echoed upstream: functionCall.id=%v functionResponse.id=%v, want gem-fc-7f3a on both (%s)", callID, respID, raw)
	}
}

// A tool result resolves its functionResponse.name against the assistant turn
// it answers. Even if an id repeats across turns (a history minted before ids
// were unique), turn 1's result must not take the name of turn 2's tool.
func TestGemini_ToolResultNameScopedToItsTurn(t *testing.T) {
	out := buildGeminiRequest(CompletionRequest{
		Model: "gemini-2.5-flash",
		Messages: []Message{
			{Role: "user", Content: "scan"},
			{Role: "assistant", ToolCalls: []ToolCall{{ID: "call_0", Name: "list_files"}}},
			{Role: "tool", ToolCallID: "call_0", Content: "a.go"},
			{Role: "assistant", ToolCalls: []ToolCall{{ID: "call_0", Name: "read_file"}}},
			{Role: "tool", ToolCallID: "call_0", Content: "package a"},
		},
	})
	var names []string
	for _, c := range out.Contents {
		for _, p := range c.Parts {
			if p.FunctionResponse != nil {
				names = append(names, p.FunctionResponse.Name)
			}
		}
	}
	if strings.Join(names, ",") != "list_files,read_file" {
		t.Errorf("functionResponse names = %v, want [list_files read_file]", names)
	}
}

// A blank tool_call_id is not a key: a tool result without one keeps its own
// m.Name rather than taking the name of whichever blank-id call came last.
func TestGemini_BlankToolCallIDKeepsOwnName(t *testing.T) {
	out := buildGeminiRequest(CompletionRequest{
		Model: "gemini-2.5-flash",
		Messages: []Message{
			{Role: "user", Content: "scan"},
			{Role: "assistant", ToolCalls: []ToolCall{{Name: "read_file"}, {Name: "grep_code"}}},
			{Role: "tool", Name: "read_file", Content: "package a"},
			{Role: "tool", Name: "grep_code", Content: "no match"},
		},
	})
	var names []string
	for _, c := range out.Contents {
		for _, p := range c.Parts {
			if p.FunctionResponse != nil {
				names = append(names, p.FunctionResponse.Name)
			}
		}
	}
	if strings.Join(names, ",") != "read_file,grep_code" {
		t.Errorf("functionResponse names = %v, want [read_file grep_code]", names)
	}
}
