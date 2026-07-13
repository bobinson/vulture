package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// openAIAdapter speaks the OpenAI chat/completions wire shape. It backs both
// the first-party OpenAI adapter and the OpenAI-compatible adapter (§9); the
// two differ only in provider name and the default endpoint fallback.
type openAIAdapter struct {
	name       string
	http       *http.Client
	defaultURL string // used only when creds.BaseURL is empty (first-party OpenAI)
}

const openAIDefaultBaseURL = "https://api.openai.com/v1"

// NewOpenAIAdapter builds the first-party OpenAI chat/completions adapter.
func NewOpenAIAdapter(httpClient *http.Client) Adapter {
	return &openAIAdapter{name: "openai", http: clientOrDefault(httpClient), defaultURL: openAIDefaultBaseURL}
}

// NewOpenAICompatibleAdapter builds an adapter for any OpenAI-compatible
// endpoint (LM Studio / vLLM / locked-down LiteLLM proxy, §9/F8). It always
// targets the tenant-supplied BaseURL — there is no default fallback.
func NewOpenAICompatibleAdapter(name string, httpClient *http.Client) Adapter {
	return &openAIAdapter{name: name, http: clientOrDefault(httpClient)}
}

func clientOrDefault(c *http.Client) *http.Client {
	if c == nil {
		return http.DefaultClient
	}
	return c
}

// Name returns the configured provider identifier.
func (a *openAIAdapter) Name() string { return a.name }

// chatWireResponse mirrors the chat/completions response body we parse.
type chatWireResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content   string         `json:"content"`
			ToolCalls []wireToolCall `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *wireUsage `json:"usage"`
}

type wireUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

type wireToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// Complete performs a synchronous chat/completions call.
func (a *openAIAdapter) Complete(ctx context.Context, creds Credentials, req CompletionRequest) (*CompletionResponse, error) {
	endpoint, err := a.endpoint(creds)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(buildChatBody(req))
	if err != nil {
		return nil, fmt.Errorf("marshal completion request: %w", err)
	}

	resp, err := a.do(ctx, endpoint, creds.APIKey, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := statusError(resp.StatusCode); err != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)) // drain, never surface body (N6)
		return nil, err
	}

	var wire chatWireResponse
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return nil, fmt.Errorf("decode completion response: %w", err)
	}
	return a.toResponse(&wire, req.RequestID)
}

// endpoint resolves the chat/completions URL, honoring creds.BaseURL and
// falling back to the adapter default only when configured (first-party).
func (a *openAIAdapter) endpoint(creds Credentials) (string, error) {
	base := strings.TrimRight(creds.BaseURL, "/")
	if base == "" {
		base = strings.TrimRight(a.defaultURL, "/")
	}
	if base == "" {
		return "", fmt.Errorf("broker/provider: missing base URL for provider %q", a.name)
	}
	return base + "/chat/completions", nil
}

// do issues the POST with Bearer auth and honors ctx cancellation.
func (a *openAIAdapter) do(ctx context.Context, endpoint, apiKey string, body []byte) (*http.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := a.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, ctx.Err())
	}
	return resp, nil
}

// toResponse normalizes the wire body and enforces the usage-sanity floor.
func (a *openAIAdapter) toResponse(wire *chatWireResponse, requestID string) (*CompletionResponse, error) {
	usage, err := normalizeUsage(wire.Usage)
	if err != nil {
		return nil, err
	}
	out := &CompletionResponse{
		Model:     wire.Model,
		Provider:  a.name,
		Usage:     usage,
		RequestID: requestID,
	}
	if len(wire.Choices) > 0 {
		ch := wire.Choices[0]
		out.Content = ch.Message.Content
		out.FinishReason = ch.FinishReason
		out.ToolCalls = relayToolCalls(ch.Message.ToolCalls)
	}
	return out, nil
}
