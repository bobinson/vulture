// Package provider defines the LLM-broker provider-egress seam (feature
// 0064, §9): an Adapter interface implemented per provider (OpenAI,
// Anthropic, Gemini, Ollama, OpenAI-compatible) plus the request/response
// shapes shared across adapters. It is OpenAI-compatible by design (§5)
// so the agent just repoints its SDK client at the broker.

package provider

import (
	"context"
	"errors"
)

// ErrNotImplemented is returned by surfaces that are deliberately deferred
// (adapter Stream/Embed — feature follow-ups, not P0).
var ErrNotImplemented = errors.New("broker/provider: not implemented")

// Sentinel egress errors (map onto §5 API error codes). Callers translate
// these to provider_unavailable / all_providers_down etc.
var (
	// ErrProviderUnavailable indicates a single provider call failed
	// after retries / circuit-open.
	ErrProviderUnavailable = errors.New("broker/provider: provider unavailable")
	// ErrRateLimited indicates a 429 / load-shed.
	ErrRateLimited = errors.New("broker/provider: rate limited")
	// ErrUsageMissing indicates a non-error response with missing/zero
	// usage — a HARD error, never $0 (§11 usage-sanity floor).
	ErrUsageMissing = errors.New("broker/provider: usage missing or zero")
)

// Message is a single chat message (OpenAI-shaped).
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	Name       string     `json:"name,omitempty"`
}

// ToolCall is a model-emitted tool-call intent. The broker relays it under
// count/arg-byte bounds (§9/H2) — it NEVER executes the tool (§11).
type ToolCall struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ToolDef is a tool definition passed through to the provider (tools
// passthrough, §18).
type ToolDef struct {
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

// Usage carries token counts and cost. Estimated is set when tokens were
// inferred rather than reported (partial/disconnected stream, §8).
type Usage struct {
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd"`
	Estimated    bool    `json:"estimated"`
}

// CompletionRequest is the normalized, adapter-agnostic completion input
// (§5). Content fields are secret-class — never logged (N6).
type CompletionRequest struct {
	RunID          string
	TenantID       string
	TaskType       string
	Model          string
	Messages       []Message
	Tools          []ToolDef
	ToolChoice     string
	MaxTokens      int
	Temperature    float64
	Stream         bool
	ResponseFormat string
	RequestID      string
}

// CompletionResponse is the non-stream completion result (§5).
type CompletionResponse struct {
	Model        string     `json:"model"`
	Provider     string     `json:"provider"`
	Content      string     `json:"content"`
	ToolCalls    []ToolCall `json:"tool_calls,omitempty"`
	FinishReason string     `json:"finish_reason"`
	Usage        Usage      `json:"usage"`
	Cached       bool       `json:"cached"`
	RequestID    string     `json:"request_id"`
}

// StreamChunk is one streaming delta or the terminal usage frame (§5).
type StreamChunk struct {
	Delta         string    `json:"delta,omitempty"`
	ToolCallDelta *ToolCall `json:"tool_call_delta,omitempty"`
	Usage         *Usage    `json:"usage,omitempty"`
	Done          bool      `json:"done,omitempty"`
	RequestID     string    `json:"request_id"`
}

// EmbeddingRequest is the normalized embeddings input (§5).
type EmbeddingRequest struct {
	RunID     string
	TenantID  string
	Model     string
	Inputs    []string
	RequestID string
}

// EmbeddingResponse is the embeddings result (§5).
type EmbeddingResponse struct {
	Model      string      `json:"model"`
	Provider   string      `json:"provider"`
	Embeddings [][]float32 `json:"embeddings"`
	Usage      Usage       `json:"usage"`
	RequestID  string      `json:"request_id"`
}

// Credentials carry the resolved per-tenant provider key + endpoint. The
// BaseURL is untrusted and MUST be SSRF-validated on every use (§11).
type Credentials struct {
	Provider string
	APIKey   string // secret-class — never logged
	BaseURL  string
	Region   string
	// PinnedIP is the SSRF-resolved address the transport MUST dial (never
	// re-resolving BaseURL's hostname) to defeat DNS-rebinding TOCTOU (§11).
	// Empty = no pin (first-party default endpoints).
	PinnedIP string
}

// KeyResolver resolves the provider API key the broker holds for egress
// (N1: keys live ONLY in the broker; plugins/agents never see them). An
// unknown provider resolves to "" (adapters omit the Authorization header).
type KeyResolver interface {
	// KeyFor returns the API key for the named provider, or "".
	KeyFor(provider string) string
}

// StaticKeys is a map-backed KeyResolver (config/env-loaded at wiring time).
type StaticKeys map[string]string

// KeyFor returns the key for provider, or "".
func (k StaticKeys) KeyFor(provider string) string { return k[provider] }

// Compile-time interface assertion.
var _ KeyResolver = StaticKeys(nil)

// Adapter is the per-provider egress seam (§9). Implementations translate
// the normalized request to the provider wire format, enforce the per-call
// context deadline, and normalize usage/errors back.
type Adapter interface {
	// Name is the provider identifier (e.g. "openai", "anthropic").
	Name() string
	// Complete performs a synchronous completion.
	Complete(ctx context.Context, creds Credentials, req CompletionRequest) (*CompletionResponse, error)
	// Stream performs a streaming completion, delivering chunks on the
	// returned channel until a terminal Done frame or ctx cancellation.
	Stream(ctx context.Context, creds Credentials, req CompletionRequest) (<-chan StreamChunk, error)
	// Embed performs a (possibly batched) embeddings request.
	Embed(ctx context.Context, creds Credentials, req EmbeddingRequest) (*EmbeddingResponse, error)
}
