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
	"time"
)

// These tests define the contract for the OpenAI and OpenAI-compatible
// chat/completions adapters (feature 0064 §9/§11). They mock ONLY the HTTP
// boundary via httptest; adapter behavior is exercised for real.
//
// The adapters under test do not exist yet:
//   - NewOpenAIAdapter(httpClient) Adapter
//   - NewOpenAICompatibleAdapter(providerName string, httpClient) Adapter
// so this package will not compile until the module agent adds them — RED.

// recordedChatResponse is a well-formed OpenAI chat/completions body with
// non-zero usage. Adapters must parse content, finish_reason, and usage.
const recordedChatResponse = `{
  "id": "chatcmpl-abc123",
  "object": "chat.completion",
  "model": "gpt-4o-2024-08-06",
  "choices": [
    {
      "index": 0,
      "message": {"role": "assistant", "content": "Hello from the model."},
      "finish_reason": "stop"
    }
  ],
  "usage": {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19}
}`

// recordedToolCallResponse exercises tools-passthrough (§18): the model
// emits a tool_call the broker must relay (never execute).
const recordedToolCallResponse = `{
  "id": "chatcmpl-tool1",
  "object": "chat.completion",
  "model": "gpt-4o-2024-08-06",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": null,
        "tool_calls": [
          {
            "id": "call_1",
            "type": "function",
            "function": {"name": "read_file", "arguments": "{\"path\":\"main.go\"}"}
          }
        ]
      },
      "finish_reason": "tool_calls"
    }
  ],
  "usage": {"prompt_tokens": 30, "completion_tokens": 15, "total_tokens": 45}
}`

// recordedZeroUsageResponse is a non-error response with zero usage. The
// usage-sanity floor (§11) demands this be a HARD error, never $0.
const recordedZeroUsageResponse = `{
  "id": "chatcmpl-zero",
  "object": "chat.completion",
  "model": "gpt-4o-2024-08-06",
  "choices": [
    {
      "index": 0,
      "message": {"role": "assistant", "content": "no usage here"},
      "finish_reason": "stop"
    }
  ],
  "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
}`

// recordedMissingUsageResponse omits the usage object entirely.
const recordedMissingUsageResponse = `{
  "id": "chatcmpl-nousage",
  "object": "chat.completion",
  "model": "gpt-4o-2024-08-06",
  "choices": [
    {
      "index": 0,
      "message": {"role": "assistant", "content": "no usage field"},
      "finish_reason": "stop"
    }
  ]
}`

// mockProvider spins up an httptest server that records the last request it
// saw and replies with a fixed status + body.
type mockProvider struct {
	srv        *httptest.Server
	lastPath   string
	lastAuth   string
	lastBody   map[string]any
	lastMethod string
}

func newMockProvider(t *testing.T, status int, body string) *mockProvider {
	t.Helper()
	m := &mockProvider{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.lastPath = r.URL.Path
		m.lastAuth = r.Header.Get("Authorization")
		m.lastMethod = r.Method
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &m.lastBody)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func baseCompletionReq() CompletionRequest {
	return CompletionRequest{
		RunID:       "run-1",
		TenantID:    "local",
		TaskType:    "chaos",
		Model:       "gpt-4o",
		Messages:    []Message{{Role: "user", Content: "hi"}},
		MaxTokens:   256,
		Temperature: 0,
		RequestID:   "req-1",
	}
}

// --- Happy path: OpenAI adapter parses content + usage --------------------

func TestOpenAIAdapter_Complete_HappyPath(t *testing.T) {
	mock := newMockProvider(t, http.StatusOK, recordedChatResponse)
	ad := NewOpenAIAdapter(mock.srv.Client())

	creds := Credentials{Provider: "openai", APIKey: "sk-test", BaseURL: mock.srv.URL}
	resp, err := ad.Complete(context.Background(), creds, baseCompletionReq())
	if err != nil {
		t.Fatalf("Complete: unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("Complete: nil response")
	}
	if resp.Content != "Hello from the model." {
		t.Errorf("Content = %q, want %q", resp.Content, "Hello from the model.")
	}
	if resp.FinishReason != "stop" {
		t.Errorf("FinishReason = %q, want stop", resp.FinishReason)
	}
	if resp.Usage.InputTokens != 12 || resp.Usage.OutputTokens != 7 {
		t.Errorf("Usage tokens = (%d,%d), want (12,7)", resp.Usage.InputTokens, resp.Usage.OutputTokens)
	}
	if resp.Usage.Estimated {
		t.Error("Usage.Estimated = true, want false for reported usage")
	}
	if resp.RequestID != "req-1" {
		t.Errorf("RequestID = %q, want req-1 (echoed)", resp.RequestID)
	}
	if resp.Provider != "openai" {
		t.Errorf("Provider = %q, want openai", resp.Provider)
	}
}

// --- Adapter hits the chat/completions path with Bearer auth --------------

func TestOpenAIAdapter_Complete_RequestShape(t *testing.T) {
	mock := newMockProvider(t, http.StatusOK, recordedChatResponse)
	ad := NewOpenAIAdapter(mock.srv.Client())

	creds := Credentials{Provider: "openai", APIKey: "sk-secret", BaseURL: mock.srv.URL}
	if _, err := ad.Complete(context.Background(), creds, baseCompletionReq()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !strings.HasSuffix(mock.lastPath, "/chat/completions") {
		t.Errorf("path = %q, want .../chat/completions", mock.lastPath)
	}
	if mock.lastMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", mock.lastMethod)
	}
	if mock.lastAuth != "Bearer sk-secret" {
		t.Errorf("Authorization = %q, want Bearer sk-secret", mock.lastAuth)
	}
	if mock.lastBody["model"] != "gpt-4o" {
		t.Errorf("body model = %v, want gpt-4o", mock.lastBody["model"])
	}
	if _, ok := mock.lastBody["messages"]; !ok {
		t.Error("body missing messages field")
	}
}

// --- Tools passthrough: tool_calls relayed, not executed (§18) ------------

func TestOpenAIAdapter_Complete_ToolCallPassthrough(t *testing.T) {
	mock := newMockProvider(t, http.StatusOK, recordedToolCallResponse)
	ad := NewOpenAIAdapter(mock.srv.Client())

	req := baseCompletionReq()
	req.Tools = []ToolDef{{
		Type:       "function",
		Name:       "read_file",
		Parameters: map[string]any{"type": "object"},
	}}
	req.ToolChoice = "auto"

	creds := Credentials{Provider: "openai", APIKey: "sk-test", BaseURL: mock.srv.URL}
	resp, err := ad.Complete(context.Background(), creds, req)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	// Tool defs must be forwarded to the provider (passthrough).
	if _, ok := mock.lastBody["tools"]; !ok {
		t.Error("body missing tools passthrough field")
	}
	if mock.lastBody["tool_choice"] != "auto" {
		t.Errorf("tool_choice = %v, want auto", mock.lastBody["tool_choice"])
	}
	// The response tool_calls must be relayed back verbatim.
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("ToolCalls len = %d, want 1", len(resp.ToolCalls))
	}
	tc := resp.ToolCalls[0]
	if tc.ID != "call_1" || tc.Name != "read_file" {
		t.Errorf("ToolCall = %+v, want id=call_1 name=read_file", tc)
	}
	if tc.Arguments != `{"path":"main.go"}` {
		t.Errorf("ToolCall.Arguments = %q, want {\"path\":\"main.go\"}", tc.Arguments)
	}
	if resp.FinishReason != "tool_calls" {
		t.Errorf("FinishReason = %q, want tool_calls", resp.FinishReason)
	}
}

// --- Usage-sanity floor: zero usage is a HARD error (§11) -----------------

func TestOpenAIAdapter_Complete_ZeroUsageIsError(t *testing.T) {
	mock := newMockProvider(t, http.StatusOK, recordedZeroUsageResponse)
	ad := NewOpenAIAdapter(mock.srv.Client())

	creds := Credentials{Provider: "openai", APIKey: "sk-test", BaseURL: mock.srv.URL}
	resp, err := ad.Complete(context.Background(), creds, baseCompletionReq())
	if err == nil {
		t.Fatalf("Complete: expected error for zero usage, got resp=%+v", resp)
	}
	if !errors.Is(err, ErrUsageMissing) {
		t.Errorf("error = %v, want ErrUsageMissing", err)
	}
}

func TestOpenAIAdapter_Complete_MissingUsageIsError(t *testing.T) {
	mock := newMockProvider(t, http.StatusOK, recordedMissingUsageResponse)
	ad := NewOpenAIAdapter(mock.srv.Client())

	creds := Credentials{Provider: "openai", APIKey: "sk-test", BaseURL: mock.srv.URL}
	_, err := ad.Complete(context.Background(), creds, baseCompletionReq())
	if !errors.Is(err, ErrUsageMissing) {
		t.Errorf("error = %v, want ErrUsageMissing for absent usage object", err)
	}
}

// --- Cost floor: a successful, non-error response never costs $0 ----------

func TestOpenAIAdapter_Complete_CostNeverZeroOnSuccess(t *testing.T) {
	mock := newMockProvider(t, http.StatusOK, recordedChatResponse)
	ad := NewOpenAIAdapter(mock.srv.Client())

	creds := Credentials{Provider: "openai", APIKey: "sk-test", BaseURL: mock.srv.URL}
	resp, err := ad.Complete(context.Background(), creds, baseCompletionReq())
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	// With reported non-zero tokens, a priced adapter must not report $0.
	if resp.Usage.CostUSD <= 0 {
		t.Errorf("CostUSD = %v, want > 0 for a metered non-error response (never $0)", resp.Usage.CostUSD)
	}
}

// --- Provider error status maps to ErrProviderUnavailable / ErrRateLimited-

func TestOpenAIAdapter_Complete_ProviderErrorMapping(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr error
	}{
		{"500 -> unavailable", http.StatusInternalServerError, ErrProviderUnavailable},
		{"503 -> unavailable", http.StatusServiceUnavailable, ErrProviderUnavailable},
		{"429 -> rate limited", http.StatusTooManyRequests, ErrRateLimited},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := newMockProvider(t, tc.status, `{"error":{"message":"boom","type":"server_error"}}`)
			ad := NewOpenAIAdapter(mock.srv.Client())
			creds := Credentials{Provider: "openai", APIKey: "sk-test", BaseURL: mock.srv.URL}
			_, err := ad.Complete(context.Background(), creds, baseCompletionReq())
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// --- N6: provider error body content must NOT leak into the returned error-

func TestOpenAIAdapter_Complete_ErrorBodyNotLeaked(t *testing.T) {
	secret := "SECRET-PROMPT-CONTENT-do-not-leak"
	mock := newMockProvider(t, http.StatusInternalServerError,
		`{"error":{"message":"`+secret+`"}}`)
	ad := NewOpenAIAdapter(mock.srv.Client())

	creds := Credentials{Provider: "openai", APIKey: "sk-test", BaseURL: mock.srv.URL}
	_, err := ad.Complete(context.Background(), creds, baseCompletionReq())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error leaked scrubbed provider body content: %v", err)
	}
}

// --- Context cancellation is honored (§9 per-call deadline) ---------------

func TestOpenAIAdapter_Complete_ContextCancelled(t *testing.T) {
	// Server hangs so only ctx cancellation can end the call. teardown is
	// closed before the server Close so the handler goroutine always
	// unblocks even if the client's context cancellation did not tear the
	// keep-alive TCP connection down (otherwise Server.Close() deadlocks
	// waiting on the still-active connection).
	teardown := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-teardown:
		}
	}))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(teardown) })

	ad := NewOpenAIAdapter(slow.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	creds := Credentials{Provider: "openai", APIKey: "sk-test", BaseURL: slow.URL}
	if _, err := ad.Complete(ctx, creds, baseCompletionReq()); err == nil {
		t.Fatal("expected error on context deadline")
	}
}

// --- Name() identity ------------------------------------------------------

func TestOpenAIAdapter_Name(t *testing.T) {
	ad := NewOpenAIAdapter(http.DefaultClient)
	if ad.Name() != "openai" {
		t.Errorf("Name() = %q, want openai", ad.Name())
	}
}
