package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// §32.1 #5: a KEYLESS/local OpenAI-compatible endpoint ($0 cost) that omits
// usage must NOT be a hard error (the billing floor applies only to billed
// cloud providers with a broker-held key) — a valid completion is returned with
// Usage.Estimated. And a response reporting only total_tokens must be derived,
// not rejected.
func usageTestServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
}

func TestOpenAI_KeylessMissingUsage_NotError(t *testing.T) {
	const noUsage = `{"model":"local","choices":[{"message":{"content":"hi"},"finish_reason":"stop"}]}`
	srv := usageTestServer(t, noUsage)
	defer srv.Close()
	a := NewOpenAICompatibleAdapter("lmstudio", srv.Client())
	// keyless: APIKey == ""
	resp, err := a.Complete(context.Background(), Credentials{Provider: "lmstudio", BaseURL: srv.URL}, CompletionRequest{Model: "local", Messages: []Message{{Role: "user", Content: "x"}}})
	if err != nil {
		t.Fatalf("keyless missing-usage must not error, got %v", err)
	}
	if !resp.Usage.Estimated {
		t.Error("keyless missing-usage must be marked Estimated")
	}
}

func TestOpenAI_TotalTokensOnly_Derived(t *testing.T) {
	const totalOnly = `{"model":"gpt-4o","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":42}}`
	srv := usageTestServer(t, totalOnly)
	defer srv.Close()
	a := NewOpenAIAdapter(srv.Client())
	resp, err := a.Complete(context.Background(), Credentials{Provider: "openai", APIKey: "sk", BaseURL: srv.URL}, CompletionRequest{Model: "gpt-4o", Messages: []Message{{Role: "user", Content: "x"}}})
	if err != nil {
		t.Fatalf("total_tokens-only must be derived, got %v", err)
	}
	if resp.Usage.InputTokens != 42 {
		t.Errorf("total_tokens must be attributed to input, got %d", resp.Usage.InputTokens)
	}
}

func TestOpenAI_KeyedMissingUsage_StillError(t *testing.T) {
	const noUsage = `{"model":"gpt-4o","choices":[{"message":{"content":"hi"}}]}`
	srv := usageTestServer(t, noUsage)
	defer srv.Close()
	a := NewOpenAIAdapter(srv.Client())
	// keyed (billed) → floor still applies
	_, err := a.Complete(context.Background(), Credentials{Provider: "openai", APIKey: "sk", BaseURL: srv.URL}, CompletionRequest{Model: "gpt-4o", Messages: []Message{{Role: "user", Content: "x"}}})
	if !errors.Is(err, ErrUsageMissing) {
		t.Errorf("keyed missing-usage must still be ErrUsageMissing, got %v", err)
	}
}
