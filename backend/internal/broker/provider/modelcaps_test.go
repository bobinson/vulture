package provider

import (
	"encoding/json"
	"testing"
)

// §32.1 #4: sampling/token params must be model-aware. A model that rejects
// sampling (OpenAI o-series, newest Anthropic) must NOT receive temperature; an
// o-series model must receive max_completion_tokens, not max_tokens.
func TestAcceptsSamplingParams(t *testing.T) {
	accept := []string{"gpt-4o", "claude-sonnet", "gemini-2.5-flash", "qwen3:8b", "z-ai/glm-4.6", "m"}
	reject := []string{"o1", "o1-mini", "o3", "o3-mini", "o4-mini", "claude-opus-4-8", "claude-sonnet-5", "claude-fable-5"}
	for _, m := range accept {
		if !acceptsSamplingParams(m) {
			t.Errorf("%s must accept sampling params", m)
		}
	}
	for _, m := range reject {
		if acceptsSamplingParams(m) {
			t.Errorf("%s must REJECT sampling params", m)
		}
	}
	if !usesMaxCompletionTokens("o3-mini") || usesMaxCompletionTokens("gpt-4o") {
		t.Error("only o-series uses max_completion_tokens")
	}
}

func TestBuildChatBody_TemperaturePresenceAndModelGating(t *testing.T) {
	// present + accepting model → sent (incl. explicit 0, M4)
	b, _ := json.Marshal(buildChatBody(CompletionRequest{Model: "gpt-4o", Temperature: 0, HasTemperature: true, MaxTokens: 100}))
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["temperature"]; !ok {
		t.Error("explicit temperature (0) must be transmitted for an accepting model")
	}
	if _, ok := m["max_tokens"]; !ok {
		t.Error("gpt-4o uses max_tokens")
	}
	// absent → omitted
	b, _ = json.Marshal(buildChatBody(CompletionRequest{Model: "gpt-4o", HasTemperature: false}))
	m = nil
	_ = json.Unmarshal(b, &m)
	if _, ok := m["temperature"]; ok {
		t.Error("omitted temperature must not be sent as 0")
	}
	// o-series → temperature dropped even when set; max_completion_tokens used
	b, _ = json.Marshal(buildChatBody(CompletionRequest{Model: "o3-mini", Temperature: 0.5, HasTemperature: true, MaxTokens: 100}))
	m = nil
	_ = json.Unmarshal(b, &m)
	if _, ok := m["temperature"]; ok {
		t.Error("o-series must not receive temperature")
	}
	if _, ok := m["max_completion_tokens"]; !ok {
		t.Error("o-series must use max_completion_tokens")
	}
	if _, ok := m["max_tokens"]; ok {
		t.Error("o-series must NOT use max_tokens")
	}
}

func TestBuildAnthropic_TemperatureGatingAndClamp(t *testing.T) {
	// newest Anthropic → no temperature
	out := buildAnthropicRequest(CompletionRequest{Model: "claude-opus-4-8", Temperature: 0.5, HasTemperature: true, Messages: []Message{{Role: "user", Content: "x"}}})
	if out.Temperature != nil {
		t.Errorf("claude-opus-4-8 must omit temperature, got %v", *out.Temperature)
	}
	// accepting model, out-of-range temp → clamped to [0,1]
	out = buildAnthropicRequest(CompletionRequest{Model: "claude-sonnet", Temperature: 1.7, HasTemperature: true, Messages: []Message{{Role: "user", Content: "x"}}})
	if out.Temperature == nil || *out.Temperature != 1.0 {
		t.Errorf("temperature must clamp to 1.0 for anthropic, got %v", out.Temperature)
	}
	// absent → omitted
	out = buildAnthropicRequest(CompletionRequest{Model: "claude-sonnet", HasTemperature: false, Messages: []Message{{Role: "user", Content: "x"}}})
	if out.Temperature != nil {
		t.Error("omitted temperature must not be sent")
	}
}
