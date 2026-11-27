package provider

import (
	"encoding/json"
	"testing"
)

// §32.1 #4: sampling/token params must be model-aware. A model that rejects
// sampling (OpenAI o-series, newest Anthropic) must NOT receive temperature; an
// o-series model must receive max_completion_tokens, not max_tokens.
func TestAcceptsSamplingParams(t *testing.T) {
	accept := []string{"gpt-4o", "gemini-2.5-flash", "qwen3:8b", "z-ai/glm-4.6", "m",
		// Claude models released before Opus 4.7 still take sampling params.
		"claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001", "claude-opus-4-1-20250805",
		"claude-sonnet-4-20250514", "claude-3-5-sonnet-20241022", "claude-3-haiku-20240307",
		"anthropic/claude-sonnet-4-5"}
	reject := []string{"o1", "o1-mini", "o3", "o3-mini", "o4-mini",
		// Every Claude model from Opus 4.7 on rejects them (400), as does an id
		// that is not a released model: the safe default for a Claude name is
		// to omit them. Gateway spellings (anthropic/…) are Claude models too.
		"claude-opus-4-7", "claude-opus-4-8", "claude-opus-5", "claude-opus-5-5",
		"claude-sonnet-5", "claude-sonnet-5-5", "claude-haiku-5-5",
		"claude-fable-5", "claude-fable-5-2", "claude-mythos-5-2",
		"claude-sonnet", "anthropic/claude-opus-5-5", "anthropic.claude-haiku-5-5"}
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
	out = buildAnthropicRequest(CompletionRequest{Model: "claude-sonnet-4-6", Temperature: 1.7, HasTemperature: true, Messages: []Message{{Role: "user", Content: "x"}}})
	if out.Temperature == nil || *out.Temperature != 1.0 {
		t.Errorf("temperature must clamp to 1.0 for anthropic, got %v", out.Temperature)
	}
	// absent → omitted
	out = buildAnthropicRequest(CompletionRequest{Model: "claude-sonnet-4-6", HasTemperature: false, Messages: []Message{{Role: "user", Content: "x"}}})
	if out.Temperature != nil {
		t.Error("omitted temperature must not be sent")
	}
}
