package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type anthReqCapture struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	System    string          `json:"system"`
	Messages  json.RawMessage `json:"messages"`
	Tools     []struct {
		Name        string         `json:"name"`
		InputSchema map[string]any `json:"input_schema"`
	} `json:"tools"`
	Temperature *float64 `json:"temperature"`
}

func anthServer(t *testing.T, status int, respBody string, cap *anthReqCapture, hdr *http.Header) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/messages") {
			t.Errorf("path = %q, want …/v1/messages", r.URL.Path)
		}
		if hdr != nil {
			*hdr = r.Header.Clone()
		}
		if cap != nil {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, cap)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
}

func TestAnthropic_Complete_TranslatesAndParses(t *testing.T) {
	var cap anthReqCapture
	var hdr http.Header
	srv := anthServer(t, 200, `{
		"content":[{"type":"text","text":"hi there"}],
		"stop_reason":"end_turn",
		"usage":{"input_tokens":80,"output_tokens":12}
	}`, &cap, &hdr)
	defer srv.Close()

	a := NewAnthropicAdapter(srv.Client())
	resp, err := a.Complete(context.Background(), Credentials{Provider: "anthropic", APIKey: "sk-ant", BaseURL: srv.URL}, CompletionRequest{
		Model:     "claude-sonnet",
		Messages:  []Message{{Role: "system", Content: "be terse"}, {Role: "user", Content: "hi"}},
		MaxTokens: 512, Temperature: 0.0, RequestID: "req-1",
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if hdr.Get("x-api-key") != "sk-ant" {
		t.Errorf("x-api-key = %q, want sk-ant", hdr.Get("x-api-key"))
	}
	if hdr.Get("anthropic-version") == "" {
		t.Error("anthropic-version header must be set")
	}
	if cap.System != "be terse" {
		t.Errorf("system = %q, want 'be terse'", cap.System)
	}
	if cap.MaxTokens != 512 {
		t.Errorf("max_tokens = %d, want 512", cap.MaxTokens)
	}
	if resp.Content != "hi there" || resp.Provider != "anthropic" {
		t.Errorf("content/provider = %q/%q", resp.Content, resp.Provider)
	}
	if resp.Usage.InputTokens != 80 || resp.Usage.OutputTokens != 12 || resp.Usage.CostUSD <= 0 {
		t.Errorf("usage = %+v", resp.Usage)
	}
}

func TestAnthropic_Complete_ToolUse(t *testing.T) {
	var cap anthReqCapture
	srv := anthServer(t, 200, `{
		"content":[{"type":"tool_use","id":"tu_1","name":"read_file","input":{"path":"x.go"}}],
		"stop_reason":"tool_use",
		"usage":{"input_tokens":40,"output_tokens":8}
	}`, &cap, nil)
	defer srv.Close()

	a := NewAnthropicAdapter(srv.Client())
	resp, err := a.Complete(context.Background(), Credentials{Provider: "anthropic", APIKey: "k", BaseURL: srv.URL}, CompletionRequest{
		Model: "claude-sonnet", Messages: []Message{{Role: "user", Content: "read"}},
		Tools: []ToolDef{{Type: "function", Name: "read_file", Parameters: map[string]any{"type": "object"}}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if len(cap.Tools) == 0 || cap.Tools[0].Name != "read_file" || cap.Tools[0].InputSchema == nil {
		t.Errorf("tools→input_schema not translated: %+v", cap.Tools)
	}
	if len(resp.ToolCalls) != 1 || resp.ToolCalls[0].Name != "read_file" || resp.ToolCalls[0].ID != "tu_1" {
		t.Fatalf("tool_use not parsed: %+v", resp.ToolCalls)
	}
	if !strings.Contains(resp.ToolCalls[0].Arguments, "x.go") {
		t.Errorf("args = %q", resp.ToolCalls[0].Arguments)
	}
	if resp.FinishReason != "tool_calls" {
		t.Errorf("finish_reason = %q, want tool_calls", resp.FinishReason)
	}
}

func TestAnthropic_MaxTokensDefaulted(t *testing.T) {
	var cap anthReqCapture
	srv := anthServer(t, 200, `{"content":[{"type":"text","text":"x"}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":2}}`, &cap, nil)
	defer srv.Close()
	a := NewAnthropicAdapter(srv.Client())
	if _, err := a.Complete(context.Background(), Credentials{Provider: "anthropic", APIKey: "k", BaseURL: srv.URL}, CompletionRequest{
		Model: "claude-sonnet", Messages: []Message{{Role: "user", Content: "x"}}, // MaxTokens 0
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if cap.MaxTokens <= 0 {
		t.Errorf("max_tokens must be defaulted > 0 (Anthropic requires it), got %d", cap.MaxTokens)
	}
}

func TestAnthropic_UsageMissing(t *testing.T) {
	srv := anthServer(t, 200, `{"content":[{"type":"text","text":"x"}],"stop_reason":"end_turn"}`, nil, nil)
	defer srv.Close()
	a := NewAnthropicAdapter(srv.Client())
	_, err := a.Complete(context.Background(), Credentials{Provider: "anthropic", APIKey: "k", BaseURL: srv.URL}, CompletionRequest{
		Model: "claude-sonnet", Messages: []Message{{Role: "user", Content: "x"}},
	})
	if !errors.Is(err, ErrUsageMissing) {
		t.Fatalf("missing usage must be ErrUsageMissing, got %v", err)
	}
}

func TestAnthropic_RateLimited(t *testing.T) {
	srv := anthServer(t, http.StatusTooManyRequests, `{"type":"error"}`, nil, nil)
	defer srv.Close()
	a := NewAnthropicAdapter(srv.Client())
	_, err := a.Complete(context.Background(), Credentials{Provider: "anthropic", APIKey: "k", BaseURL: srv.URL}, CompletionRequest{
		Model: "claude-sonnet", Messages: []Message{{Role: "user", Content: "x"}},
	})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("429 must map to ErrRateLimited, got %v", err)
	}
}

func TestAnthropic_Name(t *testing.T) {
	if NewAnthropicAdapter(nil).Name() != "anthropic" {
		t.Error("Name must be anthropic")
	}
}

// The L5 judge sends temperature 0.1 on every call. A current Claude model
// answers that with a 400, so it must never reach Anthropic for one.
func TestAnthropic_JudgeTemperatureOmittedForCurrentModels(t *testing.T) {
	for _, model := range []string{"claude-sonnet-5-5", "claude-opus-5-5", "claude-haiku-5-5"} {
		body, err := json.Marshal(buildAnthropicRequest(CompletionRequest{
			Model: model, MaxTokens: 16000, Temperature: 0.1, HasTemperature: true,
			Messages: []Message{{Role: "user", Content: "judge this"}},
		}))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		if _, ok := m["temperature"]; ok {
			t.Errorf("%s: temperature sent, Anthropic rejects it with a 400", model)
		}
	}
	body, _ := json.Marshal(buildAnthropicRequest(CompletionRequest{
		Model: "claude-sonnet-4-6", MaxTokens: 100, Temperature: 0.1, HasTemperature: true,
		Messages: []Message{{Role: "user", Content: "x"}},
	}))
	if !strings.Contains(string(body), `"temperature":0.1`) {
		t.Errorf("claude-sonnet-4-6 accepts temperature; it must still be sent: %s", body)
	}
}

// A safety-classifier decline is HTTP 200 with stop_reason "refusal" and no
// text. It must reach the agent as the OpenAI-wire refusal (finish_reason
// content_filter + a refusal message naming the category, as LiteLLM maps it),
// not as an empty answer the judge retries and the generate phase misreads.
// The tokens were billed, so it is a metered completion, not an error.
func TestAnthropic_RefusalIsSurfacedAsContentFilter(t *testing.T) {
	srv := anthServer(t, 200, `{
		"content":[],
		"stop_reason":"refusal",
		"stop_details":{"type":"refusal","category":"cyber","explanation":"declined"},
		"usage":{"input_tokens":900,"output_tokens":3}
	}`, nil, nil)
	defer srv.Close()
	resp, err := NewAnthropicAdapter(srv.Client()).Complete(context.Background(),
		Credentials{Provider: "anthropic", APIKey: "k", BaseURL: srv.URL},
		CompletionRequest{Model: "claude-sonnet-5-5", Messages: []Message{{Role: "user", Content: "x"}}})
	if err != nil {
		t.Fatalf("a refusal is a billed completion, not an error: %v", err)
	}
	if resp.FinishReason != "content_filter" {
		t.Errorf("finish_reason = %q, want content_filter", resp.FinishReason)
	}
	if !strings.Contains(resp.Refusal, "cyber") {
		t.Errorf("refusal = %q, want it to name the category", resp.Refusal)
	}
	if resp.Usage.InputTokens != 900 || resp.Usage.CostUSD <= 0 {
		t.Errorf("a refusal is still metered: %+v", resp.Usage)
	}
}

// The category comes from the provider: anything but a short lowercase word is
// not echoed into the agent's logs and persisted degraded reason.
func TestAnthropic_RefusalCategorySanitised(t *testing.T) {
	for raw, want := range map[string]string{
		"bio": "bio", "frontier_llm": "frontier_llm", "": "unspecified",
		"<script>": "unspecified", strings.Repeat("a", 80): "unspecified",
	} {
		if got := refusalCategory(raw); got != want {
			t.Errorf("refusalCategory(%q) = %q, want %q", raw, got, want)
		}
	}
}
