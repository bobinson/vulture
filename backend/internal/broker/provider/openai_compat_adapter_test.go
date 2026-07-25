package provider

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// Contract for the OpenAI-compatible adapter (§9, F8: OpenAI-compatible incl.
// LM Studio / vLLM / a locked-down LiteLLM proxy). It speaks the identical
// chat/completions wire shape but is constructed with a caller-chosen
// provider name and always targets the tenant-supplied BaseURL.
//
// Not yet implemented:
//   NewOpenAICompatibleAdapter(name string, httpClient *http.Client) Adapter
// so this file will fail to compile — RED.

func TestOpenAICompatAdapter_Name(t *testing.T) {
	ad := NewOpenAICompatibleAdapter("litellm", http.DefaultClient)
	if ad.Name() != "litellm" {
		t.Errorf("Name() = %q, want litellm", ad.Name())
	}
}

func TestOpenAICompatAdapter_Complete_HappyPath(t *testing.T) {
	mock := newMockProvider(t, http.StatusOK, recordedChatResponse)
	ad := NewOpenAICompatibleAdapter("oa-compat", mock.srv.Client())

	creds := Credentials{Provider: "oa-compat", APIKey: "tok-123", BaseURL: mock.srv.URL}
	resp, err := ad.Complete(context.Background(), creds, baseCompletionReq())
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Content != "Hello from the model." {
		t.Errorf("Content = %q", resp.Content)
	}
	if resp.Usage.InputTokens != 12 || resp.Usage.OutputTokens != 7 {
		t.Errorf("Usage = %+v, want (12,7)", resp.Usage)
	}
	// Provider label reflects the configured compatible-provider name.
	if resp.Provider != "oa-compat" {
		t.Errorf("Provider = %q, want oa-compat", resp.Provider)
	}
}

// The compatible adapter MUST honor the tenant-supplied BaseURL verbatim
// (it is what points at the LiteLLM proxy / local model server).
func TestOpenAICompatAdapter_Complete_UsesCredsBaseURL(t *testing.T) {
	mock := newMockProvider(t, http.StatusOK, recordedChatResponse)
	ad := NewOpenAICompatibleAdapter("vllm", mock.srv.Client())

	creds := Credentials{Provider: "vllm", APIKey: "tok", BaseURL: mock.srv.URL}
	if _, err := ad.Complete(context.Background(), creds, baseCompletionReq()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !strings.HasSuffix(mock.lastPath, "/chat/completions") {
		t.Errorf("path = %q, want .../chat/completions", mock.lastPath)
	}
	if mock.lastAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want Bearer tok", mock.lastAuth)
	}
}

// Usage-sanity floor applies identically to the compatible adapter (§11).
func TestOpenAICompatAdapter_Complete_ZeroUsageIsError(t *testing.T) {
	mock := newMockProvider(t, http.StatusOK, recordedZeroUsageResponse)
	ad := NewOpenAICompatibleAdapter("vllm", mock.srv.Client())

	creds := Credentials{Provider: "vllm", APIKey: "tok", BaseURL: mock.srv.URL}
	_, err := ad.Complete(context.Background(), creds, baseCompletionReq())
	if !errors.Is(err, ErrUsageMissing) {
		t.Errorf("error = %v, want ErrUsageMissing", err)
	}
}

// Missing BaseURL must be a clean invalid-request error, not a nil-deref /
// accidental call to a default OpenAI endpoint.
func TestOpenAICompatAdapter_Complete_MissingBaseURL(t *testing.T) {
	ad := NewOpenAICompatibleAdapter("vllm", http.DefaultClient)
	creds := Credentials{Provider: "vllm", APIKey: "tok", BaseURL: ""}
	if _, err := ad.Complete(context.Background(), creds, baseCompletionReq()); err == nil {
		t.Fatal("expected error when BaseURL is empty")
	}
}
