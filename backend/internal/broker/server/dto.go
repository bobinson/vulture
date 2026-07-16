package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vulture/backend/internal/broker/provider"
)

// maxRequestBytes caps a request body (§5/§26 H4). Internal-only, but a
// compromised agent token must not be able to OOM a replica with a huge body.
const maxRequestBytes = 1 << 20 // 1 MiB

// Vulture out-of-band metadata headers (§5/§26 C1). The OpenAI wire has no
// field for task_type/request_id, so the agent sends them via the SDK client's
// default_headers. run_id/tenant_id are NEVER read here — they come from the
// verified token claims (N8).
const (
	headerTaskType  = "X-Vulture-Task-Type"
	headerRequestID = "X-Vulture-Request-Id"
)

// completeRequest is the broker's INTERNAL normalized completion input,
// populated from the OpenAI body + X-Vulture headers + token claims. RunID
// and TenantID are set from the verified claims (N8), never the wire.
type completeRequest struct {
	RunID          string
	TenantID       string
	TaskType       string
	ModelHint      string
	RequestID      string
	MaxTokens      int
	Temperature    float64
	HasTemperature bool
	ToolChoice     string
	Messages       []provider.Message
	Tools          []provider.ToolDef
}

// embedRequest is the internal normalized embeddings input.
type embedRequest struct {
	RunID     string
	TenantID  string
	Model     string
	RequestID string
	Inputs    []string
}

// openaiChatRequest is the standard OpenAI chat/completions body the agent SDK
// POSTs. Only the fields the broker pipeline needs are bound.
type openaiChatRequest struct {
	Model      string             `json:"model"`
	Messages   []provider.Message `json:"messages"`
	Tools      []openaiTool       `json:"tools"`
	ToolChoice json.RawMessage    `json:"tool_choice"`
	MaxTokens  int                `json:"max_tokens"`
	// Temperature is a pointer so an OMITTED value is distinguishable from an
	// explicit 0 (§32.1 #4) — the broker must not fabricate a 0 the client never
	// sent, and must not send temperature at all to models that reject it.
	Temperature *float64 `json:"temperature"`
	Stream      bool     `json:"stream"`
}

type openaiTool struct {
	Type     string `json:"type"`
	Function struct {
		Name       string         `json:"name"`
		Parameters map[string]any `json:"parameters"`
	} `json:"function"`
}

// openaiEmbedRequest is the standard OpenAI embeddings body.
type openaiEmbedRequest struct {
	Model string          `json:"model"`
	Input json.RawMessage `json:"input"` // string or []string
}

// decodeChatRequest reads the size-capped OpenAI body + required X-Vulture
// headers into the internal completeRequest. It rejects an over-size body
// (request_too_large), a stream:true request (unsupported), and missing
// metadata headers. run_id/tenant_id are left blank — the caller sets them
// from the token claims (N8).
func decodeChatRequest(w http.ResponseWriter, r *http.Request) (*completeRequest, *apiError) {
	var body openaiChatRequest
	if apiErr := decodeCapped(w, r, &body); apiErr != nil {
		return nil, apiErr
	}
	if body.Stream {
		return nil, errStreamUnsupported
	}
	taskType, requestID, apiErr := metadata(r)
	if apiErr != nil {
		return nil, apiErr
	}
	cr := &completeRequest{
		TaskType:   taskType,
		ModelHint:  body.Model,
		RequestID:  requestID,
		MaxTokens:  body.MaxTokens,
		ToolChoice: toolChoiceString(body.ToolChoice),
		Messages:   body.Messages,
		Tools:      toToolDefs(body.Tools),
	}
	if body.Temperature != nil {
		cr.Temperature = *body.Temperature
		cr.HasTemperature = true
	}
	return cr, nil
}

// decodeEmbedRequest reads the size-capped OpenAI embeddings body + metadata.
func decodeEmbedRequest(w http.ResponseWriter, r *http.Request) (*embedRequest, *apiError) {
	var body openaiEmbedRequest
	if apiErr := decodeCapped(w, r, &body); apiErr != nil {
		return nil, apiErr
	}
	// Embeddings: task_type is implicit ("embed") for scope, so it is not
	// required; request_id is server-generated when absent (per-call PK).
	requestID := strings.TrimSpace(r.Header.Get(headerRequestID))
	if requestID == "" {
		requestID = generateRequestID()
	}
	inputs, apiErr := embedInputs(body.Input)
	if apiErr != nil {
		return nil, apiErr
	}
	return &embedRequest{Model: body.Model, RequestID: requestID, Inputs: inputs}, nil
}

// decodeCapped enforces the body size cap and decodes JSON, distinguishing an
// over-size body (request_too_large) from a malformed one (invalid_request).
func decodeCapped(w http.ResponseWriter, r *http.Request, v any) *apiError {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errRequestTooLarge
		}
		return errInvalidRequest
	}
	return nil
}

// metadata extracts the X-Vulture headers. task_type is REQUIRED (it gates
// scope). request_id is OPTIONAL on the wire: the OpenAI SDK sets headers
// per-client (per-run), but the ledger PK must be unique per CALL, so a blank
// request_id is server-GENERATED here (a client that can set it per request
// gains cross-retry idempotency; the SDK path relies on generation). §5/§26 C1.
func metadata(r *http.Request) (taskType, requestID string, apiErr *apiError) {
	taskType = strings.TrimSpace(r.Header.Get(headerTaskType))
	if taskType == "" {
		return "", "", errMissingMetadata
	}
	requestID = strings.TrimSpace(r.Header.Get(headerRequestID))
	if requestID == "" {
		requestID = generateRequestID()
	}
	return taskType, requestID, nil
}

// generateRequestID returns a unique ledger-PK request id (128 bits of
// randomness) when the client did not supply one.
func generateRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is catastrophic; a time-based fallback keeps the
		// PK unique-enough rather than colliding on a fixed value.
		return "req-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return "req-" + hex.EncodeToString(b[:])
}

// toToolDefs converts OpenAI function tools to the internal passthrough shape.
func toToolDefs(tools []openaiTool) []provider.ToolDef {
	if len(tools) == 0 {
		return nil
	}
	out := make([]provider.ToolDef, 0, len(tools))
	for _, t := range tools {
		out = append(out, provider.ToolDef{
			Type:       t.Type,
			Name:       t.Function.Name,
			Parameters: t.Function.Parameters,
		})
	}
	return out
}

// toolChoiceString reduces the OpenAI tool_choice (string like "auto"/"none"
// or an object) to the string the passthrough forwards; an object choice is
// passed through verbatim as its JSON.
func toolChoiceString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

// embedInputs normalizes the OpenAI embeddings `input` (string or []string).
func embedInputs(raw json.RawMessage) ([]string, *apiError) {
	if len(raw) == 0 {
		return nil, errInvalidRequest
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	return nil, errInvalidRequest
}

// renderChatCompletion renders the internal completion result as a standard
// OpenAI chat.completion object, with Vulture cost/provenance as namespaced
// x_* extensions (a vanilla OpenAI client ignores unknown fields).
func renderChatCompletion(resp *provider.CompletionResponse) map[string]any {
	msg := map[string]any{"role": "assistant", "content": resp.Content}
	if len(resp.ToolCalls) > 0 {
		msg["tool_calls"] = toWireToolCalls(resp.ToolCalls)
	}
	return map[string]any{
		"id":      "chatcmpl-" + resp.RequestID,
		"object":  "chat.completion",
		"model":   resp.Model,
		"choices": []map[string]any{{"index": 0, "message": msg, "finish_reason": resp.FinishReason}},
		"usage": map[string]any{
			"prompt_tokens":     resp.Usage.InputTokens,
			"completion_tokens": resp.Usage.OutputTokens,
			"total_tokens":      resp.Usage.InputTokens + resp.Usage.OutputTokens,
		},
		"x_provider":  resp.Provider,
		"x_cost_usd":  resp.Usage.CostUSD,
		"x_estimated": resp.Usage.Estimated,
		"x_cached":    resp.Cached,
	}
}

// renderEmbeddings renders the internal embeddings result as a standard OpenAI
// embeddings response with Vulture x_* extensions.
func renderEmbeddings(resp *provider.EmbeddingResponse) map[string]any {
	data := make([]map[string]any, 0, len(resp.Embeddings))
	for i, e := range resp.Embeddings {
		data = append(data, map[string]any{"object": "embedding", "index": i, "embedding": e})
	}
	return map[string]any{
		"object": "list",
		"model":  resp.Model,
		"data":   data,
		"usage": map[string]any{
			"prompt_tokens": resp.Usage.InputTokens,
			"total_tokens":  resp.Usage.InputTokens + resp.Usage.OutputTokens,
		},
		"x_provider":  resp.Provider,
		"x_cost_usd":  resp.Usage.CostUSD,
		"x_estimated": resp.Usage.Estimated,
	}
}

// toWireToolCalls maps relayed tool calls to the OpenAI wire shape.
func toWireToolCalls(calls []provider.ToolCall) []map[string]any {
	out := make([]map[string]any, 0, len(calls))
	for _, c := range calls {
		out = append(out, map[string]any{
			"id": c.ID, "type": c.Type,
			"function": map[string]any{"name": c.Name, "arguments": c.Arguments},
		})
	}
	return out
}

// writeJSON encodes v as JSON with the given status. Errors here cannot leak
// request content (v is server-built), so a bare 500 is safe.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr renders a typed apiError as the OpenAI error envelope (§5/N6). The
// body carries only the static message/type/code — never a secret.
func writeErr(w http.ResponseWriter, e *apiError) {
	writeJSON(w, e.status, map[string]any{
		"error": map[string]any{
			"message":     e.message,
			"type":        e.code,
			"code":        e.code,
			"x_retriable": e.retriable,
		},
	})
}
