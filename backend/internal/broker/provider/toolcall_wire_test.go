package provider

import (
	"encoding/json"
	"testing"
)

// §32.1 #9b (live root cause): the OpenAI chat/completions wire NESTS a tool
// call's name+arguments under "function". When the agent SDK replays the
// assistant turn on a multi-turn tool loop, the broker must parse that nested
// shape — a flat top-level "name" bind leaves Name empty, which then produces an
// empty Gemini functionResponse.name → 400 "Name cannot be empty".
func TestToolCall_UnmarshalsNestedFunctionShape(t *testing.T) {
	const wire = `{"id":"call_0","type":"function","function":{"name":"check_injection","arguments":"{\"source_path\":\".\"}"}}`
	var tc ToolCall
	if err := json.Unmarshal([]byte(wire), &tc); err != nil {
		t.Fatal(err)
	}
	if tc.ID != "call_0" || tc.Type != "function" {
		t.Errorf("id/type not parsed: %+v", tc)
	}
	if tc.Name != "check_injection" {
		t.Errorf("nested function.name not parsed: got %q", tc.Name)
	}
	if tc.Arguments != `{"source_path":"."}` {
		t.Errorf("nested function.arguments not parsed: got %q", tc.Arguments)
	}
}

func TestToolCall_UnmarshalTolerantOfFlatShape(t *testing.T) {
	// Defensive: a flat shape (some clients / internal round-trips) still works.
	const flat = `{"id":"c1","type":"function","name":"x","arguments":"{}"}`
	var tc ToolCall
	if err := json.Unmarshal([]byte(flat), &tc); err != nil {
		t.Fatal(err)
	}
	if tc.Name != "x" || tc.Arguments != "{}" {
		t.Errorf("flat shape not parsed: %+v", tc)
	}
}

// End-to-end: an OpenAI-wire multi-turn conversation (assistant nested
// tool_calls → tool result) must yield a Gemini request whose functionResponse
// carries the RESOLVED tool name, not an empty string.
func TestGemini_MultiTurn_FromWireMessages_NameResolved(t *testing.T) {
	const messagesJSON = `[
	  {"role":"user","content":"scan"},
	  {"role":"assistant","tool_calls":[{"id":"call_0","type":"function","function":{"name":"check_injection","arguments":"{}"}}]},
	  {"role":"tool","tool_call_id":"call_0","content":"no findings"}
	]`
	var msgs []Message
	if err := json.Unmarshal([]byte(messagesJSON), &msgs); err != nil {
		t.Fatal(err)
	}
	out := buildGeminiRequest(CompletionRequest{Model: "gemini-2.5-flash", Messages: msgs})
	// find the functionResponse part
	var frName string
	for _, c := range out.Contents {
		for _, p := range c.Parts {
			if p.FunctionResponse != nil {
				frName = p.FunctionResponse.Name
			}
		}
	}
	if frName != "check_injection" {
		t.Errorf("functionResponse.name = %q, want check_injection (empty → Gemini 400)", frName)
	}
}
