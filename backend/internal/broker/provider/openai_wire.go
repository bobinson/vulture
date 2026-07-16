package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

// drainErrBody reads the error response body and ALWAYS logs the upstream error
// body on a non-2xx (truncated). The provider's error body is a DIAGNOSTIC — it
// names the rejected field / reason — not prompt/completion content, so surfacing
// it is N6-safe and is exactly what an operator needs to fix a 4xx (the whole
// reason a Gemini 400 was undiagnosable). The REQUEST body (which DOES contain
// the prompt, secret-class) is logged only under VULTURE_BROKER_DEBUG_EGRESS.
func drainErrBody(providerName string, status int, reqBody []byte, respBody io.Reader) {
	b, _ := io.ReadAll(io.LimitReader(respBody, 8<<10))
	log.Printf("broker: egress %s upstream=%d error_body=%s", providerName, status, truncStr(string(b), 2000))
	if os.Getenv("VULTURE_BROKER_DEBUG_EGRESS") != "" && len(reqBody) > 0 {
		log.Printf("broker: DEBUG egress %s request_body=%s", providerName, truncStr(string(reqBody), 16<<10))
	}
}

func truncStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…(truncated)"
	}
	return s
}

// transportError classifies a transport-level Do() failure (§32.1 #3). A
// cancelled/expired context — a client disconnect or the self-imposed
// CallTimeoutSec firing — is returned RAW (context.Canceled/DeadlineExceeded)
// so it is non-retriable and breaker-neutral; a genuine connectivity failure
// (connect-refused/DNS/TLS, nil ctx.Err()) is wrapped as the TRANSIENT
// ErrProviderUnavailable. Shared by every adapter so the classification is
// identical across providers.
func transportError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
}

// buildChatBody assembles the OpenAI chat/completions request body, forwarding
// tools/tool_choice verbatim (tools passthrough, §18 — the broker relays, never
// executes). Zero-valued optional fields are omitted via the map shape.
func buildChatBody(req CompletionRequest) map[string]any {
	body := map[string]any{
		"model":    req.Model,
		"messages": req.Messages,
	}
	// §26/M4 + §32.1 #4: send temperature only when the client EXPLICITLY set it
	// (an omitted value must not become a 0) AND the model accepts sampling
	// params (o-series reject temperature≠1). An explicit 0 (deterministic
	// sampling) is still transmitted for accepting models.
	if req.HasTemperature && acceptsSamplingParams(req.Model) {
		body["temperature"] = req.Temperature
	}
	if req.MaxTokens > 0 {
		// §32.1 #4: o-series use max_completion_tokens; max_tokens 400s.
		if usesMaxCompletionTokens(req.Model) {
			body["max_completion_tokens"] = req.MaxTokens
		} else {
			body["max_tokens"] = req.MaxTokens
		}
	}
	if req.Stream {
		body["stream"] = true
	}
	if len(req.Tools) > 0 {
		body["tools"] = toWireTools(req.Tools)
	}
	if req.ToolChoice != "" {
		body["tool_choice"] = toolChoiceWire(req.ToolChoice)
	}
	return body
}

// toolChoiceWire renders the tool_choice value onto the wire (§32.1 #7). An
// object-form choice arrives as a raw JSON string — it must be emitted as a
// json.RawMessage so it marshals as a JSON OBJECT, not double-encoded into a
// quoted string (which providers reject). A string enum ("auto"/"none"/
// "required") is emitted verbatim as a JSON string.
func toolChoiceWire(choice string) any {
	if t := strings.TrimSpace(choice); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		return json.RawMessage(t)
	}
	return choice
}

// toWireTools maps normalized tool defs onto the OpenAI function-tool shape.
func toWireTools(tools []ToolDef) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		out = append(out, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":       t.Name,
				"parameters": t.Parameters,
			},
		})
	}
	return out
}

// relayToolCalls flattens wire tool_calls into the relay shape (never executed).
func relayToolCalls(wire []wireToolCall) []ToolCall {
	if len(wire) == 0 {
		return nil
	}
	out := make([]ToolCall, 0, len(wire))
	for _, w := range wire {
		out = append(out, ToolCall{
			ID:        w.ID,
			Type:      w.Type,
			Name:      w.Function.Name,
			Arguments: w.Function.Arguments,
		})
	}
	return out
}

// statusError maps a provider HTTP status onto a CLASSIFIED sentinel egress
// error (§32.1). A 2xx yields nil. The provider body is never inspected (N6: no
// content leakage) — only the status CODE is carried in the wrapped message so
// the server-side egress log can say WHY a call failed. errors.Is still matches
// the sentinels, and the sentinel's CLASS (transient/permanent — see
// provider.go) drives retry/failover/breaker behavior:
//
//   - 429                     → ErrRateLimited        (transient, retriable)
//   - 408, 5xx                → ErrProviderUnavailable (transient, retriable)
//   - 401, 403                → ErrProviderAuth        (permanent — bad key, N1)
//   - 404, 409                → ErrModelNotFound       (permanent — bad route)
//   - 400, 413, 422, other 4xx → ErrProviderBadRequest (permanent — bad request)
//
// Mapping 4xx to a PERMANENT sentinel is what stops a malformed request (e.g.
// the Gemini tool-schema 400) from being retried 9× and tripping a false
// all_providers_down.
func statusError(status int) error {
	switch {
	case status >= 200 && status < 300:
		return nil
	case status == http.StatusTooManyRequests: // 429
		return fmt.Errorf("%w: upstream status %d", ErrRateLimited, status)
	case status == http.StatusRequestTimeout: // 408 — transient
		return fmt.Errorf("%w: upstream status %d", ErrProviderUnavailable, status)
	case status == http.StatusUnauthorized || status == http.StatusForbidden: // 401/403
		return fmt.Errorf("%w: upstream status %d", ErrProviderAuth, status)
	case status == http.StatusNotFound || status == http.StatusConflict: // 404/409
		return fmt.Errorf("%w: upstream status %d", ErrModelNotFound, status)
	case status >= 400 && status < 500: // 400/413/422/other client faults
		return fmt.Errorf("%w: upstream status %d", ErrProviderBadRequest, status)
	default: // 5xx and anything else → provider health
		return fmt.Errorf("%w: upstream status %d", ErrProviderUnavailable, status)
	}
}
