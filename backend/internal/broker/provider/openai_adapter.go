package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// openAIAdapter speaks the OpenAI chat/completions wire shape. It backs both
// the first-party OpenAI adapter and the OpenAI-compatible adapter (§9); the
// two differ only in provider name and the default endpoint fallback.
type openAIAdapter struct {
	name       string
	http       *http.Client
	defaultURL string // used only when creds.BaseURL is empty (first-party OpenAI)
	// pinnedClients caches one IP-pinning client per pinned IP (§26/M1) so the
	// hot path — egressCheck pins EVERY candidate — reuses connections instead
	// of allocating a fresh transport + pool per request.
	pinnedClients sync.Map // pinnedIP string → *http.Client
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
	TotalTokens      int `json:"total_tokens"`
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

	resp, err := a.do(ctx, endpoint, creds, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := statusError(resp.StatusCode); err != nil {
		drainErrBody(a.name, resp.StatusCode, body, resp.Body) // N6: drain; log only under debug flag
		return nil, err
	}

	var wire chatWireResponse
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return nil, fmt.Errorf("decode completion response: %w", err)
	}
	// §32.1 #5: keyless == a local/$0 endpoint → the usage floor is relaxed.
	return a.toResponse(&wire, req.RequestID, creds.APIKey == "")
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

// do issues the POST with Bearer auth and honors ctx cancellation. When the
// credentials carry an SSRF-pinned IP, the transport dials it directly.
func (a *openAIAdapter) do(ctx context.Context, endpoint string, creds Credentials, body []byte) (*http.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if creds.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+creds.APIKey)
	}
	resp, err := a.client(creds.PinnedIP).Do(httpReq)
	if err != nil {
		// §26/M5 + §32.1 #3: a cancelled/expired ctx surfaces raw (non-retriable,
		// breaker-neutral); a real connectivity failure is TRANSIENT.
		return nil, transportError(ctx, err)
	}
	return resp, nil
}

// client returns the adapter's HTTP client, IP-pinned when the SSRF validator
// resolved an address (§11). Delegates to the shared pinnedClient helper so
// every adapter uses one implementation.
func (a *openAIAdapter) client(pinnedIP string) *http.Client {
	return pinnedClient(a.http, &a.pinnedClients, pinnedIP)
}

// toResponse normalizes the wire body and enforces the usage-sanity floor
// (relaxed for keyless/local $0 endpoints, §32.1 #5).
func (a *openAIAdapter) toResponse(wire *chatWireResponse, requestID string, keyless bool) (*CompletionResponse, error) {
	usage, err := normalizeUsage(wire.Usage, wire.Model, keyless)
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
