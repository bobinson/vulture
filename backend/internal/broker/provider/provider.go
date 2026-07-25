// Package provider defines the LLM-broker provider-egress seam (feature
// 0064, §9): an Adapter interface implemented per provider (OpenAI,
// Anthropic, Gemini, Ollama, OpenAI-compatible) plus the request/response
// shapes shared across adapters. It is OpenAI-compatible by design (§5)
// so the agent just repoints its SDK client at the broker.

package provider

import (
	"context"
	"encoding/json"
	"errors"
)

// ErrNotImplemented is returned by surfaces that are deliberately deferred
// (adapter Stream/Embed — feature follow-ups, not P0).
var ErrNotImplemented = errors.New("broker/provider: not implemented")

// Sentinel egress errors (map onto §5 API error codes). Callers translate
// these to provider_unavailable / all_providers_down etc.
//
// §32.1 taxonomy — every egress error is one of three CLASSES, which decide
// retry, failover, and breaker accounting:
//
//   - TRANSIENT (ErrProviderUnavailable, ErrRateLimited): the PROVIDER is
//     unhealthy → retriable, failover-eligible, COUNTS toward the breaker.
//   - PERMANENT client/config (ErrProviderBadRequest, ErrProviderAuth,
//     ErrModelNotFound): the REQUEST/key/model is wrong → NOT retriable, NOT
//     failover (it would fail identically elsewhere), breaker-NEUTRAL (a bad
//     request is not a provider outage — this is what turned a single 400 into
//     a 9× retry + false all_providers_down).
//   - NEUTRAL (ErrUsageMissing, context cancellation): a served-but-unmetered
//     response or a self-imposed deadline — never counts against the provider.
var (
	// ErrProviderUnavailable indicates a single provider call failed
	// after retries / circuit-open (conn error, 5xx, 408). TRANSIENT.
	ErrProviderUnavailable = errors.New("broker/provider: provider unavailable")
	// ErrRateLimited indicates a 429 / load-shed. TRANSIENT.
	ErrRateLimited = errors.New("broker/provider: rate limited")
	// ErrProviderBadRequest indicates the provider rejected the request as
	// malformed (400/413/422) — a translation/schema/size fault the client
	// cannot fix by retrying. PERMANENT.
	ErrProviderBadRequest = errors.New("broker/provider: provider rejected request")
	// ErrProviderAuth indicates an auth/permission failure (401/403) on the
	// broker-held key — the agent cannot remediate it (N1). PERMANENT.
	ErrProviderAuth = errors.New("broker/provider: provider auth failed")
	// ErrModelNotFound indicates the model/route does not exist (404/409) —
	// a typo/deprecated/unrouted model. PERMANENT.
	ErrModelNotFound = errors.New("broker/provider: model not found")
	// ErrUsageMissing indicates a non-error response with missing/zero
	// usage — a HARD error for BILLED cloud calls (§11 usage-sanity floor),
	// but breaker-NEUTRAL (the completion itself succeeded).
	ErrUsageMissing = errors.New("broker/provider: usage missing or zero")
)

// IsPermanent reports whether err is a permanent client/config fault that must
// NOT be retried or failed over (§32.1) — a retry/failover would fail
// identically. Transient provider errors are the complement.
func IsPermanent(err error) bool {
	return errors.Is(err, ErrProviderBadRequest) ||
		errors.Is(err, ErrProviderAuth) ||
		errors.Is(err, ErrModelNotFound)
}

// IsProviderHealthFailure reports whether err reflects the PROVIDER being
// unhealthy — the only class that should count toward opening the
// per-(provider,model) circuit breaker (§32.1). Permanent client faults,
// usage-missing, and context cancellation are breaker-NEUTRAL: a request-shape
// bug or a self-imposed deadline must not masquerade as a provider outage and
// trip a cross-tenant breaker.
func IsProviderHealthFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return errors.Is(err, ErrProviderUnavailable) || errors.Is(err, ErrRateLimited)
}

// Message is a single chat message (OpenAI-shaped).
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	Name       string     `json:"name,omitempty"`
}

// ToolCall is a model-emitted tool-call intent. The broker relays it under
// count/arg-byte bounds (§9/H2) — it NEVER executes the tool (§11). Internally
// the name/arguments are flat; on the wire they are OpenAI-nested (see
// UnmarshalJSON).
type ToolCall struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// UnmarshalJSON parses a tool call from the OpenAI chat/completions wire, where
// name+arguments are NESTED under "function" (§32.1 #9b). This is the shape the
// agent SDK replays on a multi-turn tool loop; a flat-only bind would leave Name
// empty and produce an empty Gemini functionResponse.name / Anthropic tool name
// → provider 400. A flat top-level name/arguments is still accepted as a
// fallback (internal round-trips, lenient clients).
func (tc *ToolCall) UnmarshalJSON(data []byte) error {
	var w struct {
		ID        string `json:"id"`
		Type      string `json:"type"`
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
		Function  *struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	tc.ID, tc.Type, tc.Name, tc.Arguments = w.ID, w.Type, w.Name, w.Arguments
	if w.Function != nil { // nested wins — the OpenAI standard shape
		if w.Function.Name != "" {
			tc.Name = w.Function.Name
		}
		if w.Function.Arguments != "" {
			tc.Arguments = w.Function.Arguments
		}
	}
	return nil
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
	RunID       string
	TenantID    string
	TaskType    string
	Model       string
	Messages    []Message
	Tools       []ToolDef
	ToolChoice  string
	MaxTokens   int
	Temperature float64
	// HasTemperature distinguishes an explicit temperature (incl. 0 — the
	// deterministic default, M4) from an OMITTED one (§32.1 #4). An omitted
	// temperature must NOT be sent as 0, and a model that rejects sampling
	// params (o-series, newest Anthropic) must not receive it at all.
	HasTemperature bool
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

// CanonicalBaseURL returns the well-known default egress endpoint for a
// first-party provider (§30). The broker needs a concrete base URL BEFORE the
// adapter runs — egress SSRF-validates + IP-pins it (§11) — so a native cloud
// provider (gemini/anthropic) cannot rely on the adapter's internal fallback
// alone. Returns "" for providers that have no canonical endpoint (e.g.
// openai-compatible / a local server MUST supply its own base URL).
func CanonicalBaseURL(providerName string) string {
	switch providerName {
	case "openai":
		return openAIDefaultBaseURL
	case "gemini":
		return geminiDefaultBaseURL
	case "anthropic":
		return anthropicDefaultBaseURL
	default:
		return ""
	}
}

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
