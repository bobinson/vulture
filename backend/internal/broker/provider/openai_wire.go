package provider

import "net/http"

// buildChatBody assembles the OpenAI chat/completions request body, forwarding
// tools/tool_choice verbatim (tools passthrough, §18 — the broker relays, never
// executes). Zero-valued optional fields are omitted via the map shape.
func buildChatBody(req CompletionRequest) map[string]any {
	body := map[string]any{
		"model":    req.Model,
		"messages": req.Messages,
	}
	if req.MaxTokens > 0 {
		body["max_tokens"] = req.MaxTokens
	}
	if req.Temperature != 0 {
		body["temperature"] = req.Temperature
	}
	if req.Stream {
		body["stream"] = true
	}
	if len(req.Tools) > 0 {
		body["tools"] = toWireTools(req.Tools)
	}
	if req.ToolChoice != "" {
		body["tool_choice"] = req.ToolChoice
	}
	return body
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

// statusError maps a provider HTTP status onto a sentinel egress error. A 2xx
// yields nil. The provider body is never inspected (N6: no content leakage).
func statusError(status int) error {
	if status >= 200 && status < 300 {
		return nil
	}
	if status == http.StatusTooManyRequests {
		return ErrRateLimited
	}
	return ErrProviderUnavailable
}
