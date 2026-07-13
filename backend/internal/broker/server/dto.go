package server

import (
	"encoding/json"
	"net/http"

	"github.com/vulture/backend/internal/broker/provider"
)

// completeRequest is the OpenAI-shaped completion body accepted at §5. Prompt
// and tool-call content are secret-class and never logged (N6).
type completeRequest struct {
	RunID          string             `json:"run_id"`
	TenantID       string             `json:"tenant_id"`
	TaskType       string             `json:"task_type"`
	ModelHint      string             `json:"model_hint"`
	RequestID      string             `json:"request_id"`
	MaxTokens      int                `json:"max_tokens"`
	Temperature    float64            `json:"temperature"`
	Stream         bool               `json:"stream"`
	ResponseFormat string             `json:"response_format"`
	ToolChoice     string             `json:"tool_choice"`
	Messages       []provider.Message `json:"messages"`
	Tools          []provider.ToolDef `json:"tools"`
}

// embedRequest is the OpenAI-shaped embeddings body accepted at §5.
type embedRequest struct {
	RunID     string   `json:"run_id"`
	TenantID  string   `json:"tenant_id"`
	Model     string   `json:"model"`
	RequestID string   `json:"request_id"`
	Inputs    []string `json:"inputs"`
}

// writeJSON encodes v as JSON with the given status. Errors here cannot leak
// request content (v is server-built), so a bare 500 is safe.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr renders a typed apiError as the structured envelope (§5/N6). The
// body carries only the static code/message/retriable — never a secret.
func writeErr(w http.ResponseWriter, e *apiError) {
	writeJSON(w, e.status, map[string]any{
		"error": map[string]any{
			"code":      e.code,
			"message":   e.message,
			"retriable": e.retriable,
		},
	})
}
