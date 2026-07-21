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

// anthropicAdapter speaks Anthropic's native Messages API (feature 0064 §30).
// It translates the normalized OpenAI-shaped CompletionRequest to Messages
// (system extracted, tool_use / tool_result blocks) and normalizes content
// blocks + usage back — Anthropic has no OpenAI-compat endpoint, so this is
// the only way to broker it.
type anthropicAdapter struct {
	name          string
	http          *http.Client
	defaultURL    string
	version       string
	pinnedClients sync.Map
}

const (
	anthropicDefaultBaseURL = "https://api.anthropic.com"
	anthropicVersion        = "2023-06-01"
	anthropicMaxTokensFloor = 4096 // Messages requires max_tokens > 0
)

// NewAnthropicAdapter builds the native Anthropic Messages adapter.
func NewAnthropicAdapter(httpClient *http.Client) Adapter {
	return &anthropicAdapter{name: "anthropic", http: clientOrDefault(httpClient), defaultURL: anthropicDefaultBaseURL, version: anthropicVersion}
}

func (a *anthropicAdapter) Name() string { return a.name }

// --- wire shapes ---

type anthTextBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
type anthToolUseBlock struct {
	Type  string          `json:"type"`
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}
type anthToolResultBlock struct {
	Type      string `json:"type"`
	ToolUseID string `json:"tool_use_id"`
	Content   string `json:"content"`
}
type anthMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // string OR []block
}
type anthTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"input_schema"`
}
type anthRequest struct {
	Model       string        `json:"model"`
	MaxTokens   int           `json:"max_tokens"`
	System      string        `json:"system,omitempty"`
	Messages    []anthMessage `json:"messages"`
	Tools       []anthTool    `json:"tools,omitempty"`
	ToolChoice  any           `json:"tool_choice,omitempty"`
	Temperature *float64      `json:"temperature,omitempty"`
}

type anthResponse struct {
	Content []struct {
		Type  string          `json:"type"`
		Text  string          `json:"text"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      *struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// Complete performs a synchronous Messages call.
func (a *anthropicAdapter) Complete(ctx context.Context, creds Credentials, req CompletionRequest) (*CompletionResponse, error) {
	base := strings.TrimRight(creds.BaseURL, "/")
	if base == "" {
		base = strings.TrimRight(a.defaultURL, "/")
	}
	if base == "" {
		return nil, fmt.Errorf("broker/provider: missing base URL for anthropic")
	}
	body, err := json.Marshal(buildAnthropicRequest(req))
	if err != nil {
		return nil, fmt.Errorf("marshal anthropic request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("anthropic-version", a.version)
	if creds.APIKey != "" {
		httpReq.Header.Set("x-api-key", creds.APIKey)
	}
	resp, err := pinnedClient(a.http, &a.pinnedClients, creds.PinnedIP).Do(httpReq)
	if err != nil {
		return nil, transportError(ctx, err) // §32.1 #3
	}
	defer resp.Body.Close()
	if err := statusError(resp.StatusCode); err != nil {
		drainErrBody(a.name, resp.StatusCode, body, resp.Body) // N6: drain; log only under debug flag
		return nil, err
	}
	var wire anthResponse
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return nil, fmt.Errorf("decode anthropic response: %w", err)
	}
	return a.toResponse(&wire, req.Model, req.RequestID)
}

// buildAnthropicRequest translates the normalized request to Messages wire.
func buildAnthropicRequest(req CompletionRequest) anthRequest {
	out := anthRequest{Model: req.Model, MaxTokens: req.MaxTokens}
	if out.MaxTokens <= 0 {
		out.MaxTokens = anthropicMaxTokensFloor
	}
	var sys []string
	for _, m := range req.Messages {
		switch m.Role {
		case "system":
			if m.Content != "" {
				sys = append(sys, m.Content)
			}
		case "tool":
			out.Messages = append(out.Messages, anthMessage{Role: "user", Content: []anthToolResultBlock{{
				Type: "tool_result", ToolUseID: m.ToolCallID, Content: m.Content,
			}}})
		case "assistant":
			if len(m.ToolCalls) > 0 {
				blocks := make([]anthToolUseBlock, 0, len(m.ToolCalls))
				for _, tc := range m.ToolCalls {
					blocks = append(blocks, anthToolUseBlock{Type: "tool_use", ID: tc.ID, Name: tc.Name, Input: json.RawMessage(orJSONNull(tc.Arguments))})
				}
				out.Messages = append(out.Messages, anthMessage{Role: "assistant", Content: blocks})
			} else {
				out.Messages = append(out.Messages, anthMessage{Role: "assistant", Content: m.Content})
			}
		default: // user
			out.Messages = append(out.Messages, anthMessage{Role: "user", Content: m.Content})
		}
	}
	if len(sys) > 0 {
		out.System = strings.Join(sys, "\n")
	}
	for _, t := range req.Tools {
		out.Tools = append(out.Tools, anthTool{Name: t.Name, InputSchema: anthropicInputSchema(t.Parameters)})
	}
	// §32.1 #8: Anthropic 400s on tool_choice without tools — only emit it when
	// tools are actually attached.
	if len(out.Tools) > 0 {
		if tc := mapAnthToolChoice(req.ToolChoice); tc != nil {
			out.ToolChoice = tc
		}
	}
	// §32.1 #4: send temperature only when explicitly set AND the model accepts
	// sampling params (newest Anthropic models removed them). Clamp to Anthropic's
	// [0,1] range (an OpenAI-range value like 1.5 would 400).
	if req.HasTemperature && acceptsSamplingParams(req.Model) {
		temp := clampTemp(req.Temperature, 0, 1)
		out.Temperature = &temp
	}
	return out
}

// anthropicInputSchema ensures a tool's input_schema has an object root
// (§32.1 #15) — the Messages API requires it. A nil/typeless schema becomes a
// bare object; a schema whose root type is missing is coerced to object.
func anthropicInputSchema(schema map[string]any) map[string]any {
	if schema == nil {
		return map[string]any{"type": "object"}
	}
	if _, ok := schema["type"]; !ok {
		out := make(map[string]any, len(schema)+1)
		for k, v := range schema {
			out[k] = v
		}
		out["type"] = "object"
		return out
	}
	return schema
}

func mapAnthToolChoice(choice string) map[string]string {
	switch choice {
	case "auto":
		return map[string]string{"type": "auto"}
	case "none":
		return map[string]string{"type": "none"}
	case "required", "any":
		return map[string]string{"type": "any"}
	default:
		return nil
	}
}

func (a *anthropicAdapter) toResponse(wire *anthResponse, model, requestID string) (*CompletionResponse, error) {
	if wire.Usage == nil || wire.Usage.InputTokens+wire.Usage.OutputTokens <= 0 {
		return nil, ErrUsageMissing
	}
	in, outTok := wire.Usage.InputTokens, wire.Usage.OutputTokens
	out := &CompletionResponse{
		Model:        model,
		Provider:     a.name,
		RequestID:    requestID,
		FinishReason: mapAnthropicStop(wire.StopReason),
		Usage:        Usage{InputTokens: in, OutputTokens: outTok, CostUSD: ActualUSD(model, in, outTok)},
	}
	var text strings.Builder
	for _, b := range wire.Content {
		switch b.Type {
		case "text":
			text.WriteString(b.Text)
		case "tool_use":
			// §32.1 #11: normalize empty/null tool input to a valid JSON object.
			out.ToolCalls = append(out.ToolCalls, ToolCall{ID: b.ID, Type: "function", Name: b.Name, Arguments: orJSONNull(string(b.Input))})
		}
	}
	out.Content = text.String()
	if len(out.ToolCalls) > 0 {
		out.FinishReason = "tool_calls" // OpenAI-wire convention
	}
	return out, nil
}

func mapAnthropicStop(r string) string {
	switch r {
	case "end_turn", "stop_sequence":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	default:
		return r
	}
}

// Stream is deferred (F2); the DTO layer rejects stream:true before egress.
func (a *anthropicAdapter) Stream(context.Context, Credentials, CompletionRequest) (<-chan StreamChunk, error) {
	return nil, ErrNotImplemented
}

// Embed: Anthropic has no embeddings API (Voyage is separate) → not supported.
func (a *anthropicAdapter) Embed(context.Context, Credentials, EmbeddingRequest) (*EmbeddingResponse, error) {
	return nil, ErrNotImplemented
}

var _ Adapter = (*anthropicAdapter)(nil)
