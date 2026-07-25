package provider

import (
	"encoding/json"
	"testing"
)

// §32.1 #7: an object-form tool_choice must marshal as a JSON OBJECT, not a
// quoted string. The value arrives as a raw JSON string in req.ToolChoice.
func TestOpenAI_ObjectToolChoiceMarshalsAsObject(t *testing.T) {
	req := CompletionRequest{
		Model:      "gpt-4o",
		Messages:   []Message{{Role: "user", Content: "x"}},
		Tools:      []ToolDef{{Type: "function", Name: "x", Parameters: map[string]any{"type": "object"}}},
		ToolChoice: `{"type":"function","function":{"name":"x"}}`,
	}
	b, _ := json.Marshal(buildChatBody(req))
	var got struct {
		ToolChoice json.RawMessage `json:"tool_choice"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(got.ToolChoice, &obj); err != nil {
		t.Fatalf("object tool_choice not emitted as an object (double-encoded?): %s", got.ToolChoice)
	}
	if obj["type"] != "function" {
		t.Errorf("tool_choice object mangled: %v", obj)
	}
}

// A string-enum tool_choice must still be a JSON string.
func TestOpenAI_StringToolChoiceMarshalsAsString(t *testing.T) {
	req := CompletionRequest{
		Model: "gpt-4o", Messages: []Message{{Role: "user", Content: "x"}}, ToolChoice: "auto",
	}
	b, _ := json.Marshal(buildChatBody(req))
	var got struct {
		ToolChoice string `json:"tool_choice"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("string tool_choice should decode as string: %v", err)
	}
	if got.ToolChoice != "auto" {
		t.Errorf("tool_choice = %q, want auto", got.ToolChoice)
	}
}

// §32.1 #8: Anthropic rejects tool_choice when no tools are present. The adapter
// must omit tool_choice unless tools are attached.
func TestAnthropic_ToolChoiceOmittedWithoutTools(t *testing.T) {
	req := CompletionRequest{
		Model: "claude-sonnet", Messages: []Message{{Role: "user", Content: "x"}}, ToolChoice: "auto",
	}
	out := buildAnthropicRequest(req)
	if out.ToolChoice != nil {
		t.Errorf("tool_choice must be omitted when no tools: %+v", out.ToolChoice)
	}
	// With a tool present it should be set.
	req.Tools = []ToolDef{{Type: "function", Name: "x", Parameters: map[string]any{"type": "object", "properties": map[string]any{"p": map[string]any{"type": "string"}}}}}
	if buildAnthropicRequest(req).ToolChoice == nil {
		t.Error("tool_choice must be set when tools are present")
	}
}

// §32.1 #15: Anthropic input_schema root must be an object type.
func TestAnthropic_ToolSchemaRootCoercedToObject(t *testing.T) {
	req := CompletionRequest{
		Model:    "claude-sonnet",
		Messages: []Message{{Role: "user", Content: "x"}},
		Tools:    []ToolDef{{Type: "function", Name: "x", Parameters: map[string]any{"properties": map[string]any{"p": map[string]any{"type": "string"}}}}},
	}
	out := buildAnthropicRequest(req)
	if len(out.Tools) != 1 || out.Tools[0].InputSchema["type"] != "object" {
		t.Errorf("anthropic tool input_schema root must be object: %+v", out.Tools)
	}
}
