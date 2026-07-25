package server_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/broker/provider"
)

// §9/H2: a completion whose tool_call COUNT exceeds the per-turn cap is
// rejected with tool_output_too_large — but the incurred cost is still metered
// (reconcile ran) since the provider call happened.
func TestHandleComplete_TooManyToolCalls_Rejected(t *testing.T) {
	h := newHealthyHarness()
	calls := make([]provider.ToolCall, 100) // > cap (64)
	for i := range calls {
		calls[i] = provider.ToolCall{ID: "c", Type: "function", Name: "f", Arguments: "{}"}
	}
	h.openaiFake.resp = &provider.CompletionResponse{
		Model: "gpt-4o", Provider: "openai", FinishReason: "tool_calls",
		Usage:     provider.Usage{InputTokens: 10, OutputTokens: 5},
		ToolCalls: calls,
	}
	rr := doPost(t, h.server(), completePath, testBearer, completeBody())
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%q", rr.Code, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "tool_output_too_large" {
		t.Fatalf("code = %q, want tool_output_too_large", got)
	}
	if len(h.budget.reconciledEntries()) != 1 {
		t.Errorf("cost must still be metered (reconcile) for a call that happened; got %d entries", len(h.budget.reconciledEntries()))
	}
}

// §9/H2: aggregate argument BYTES over the cap are rejected even with few calls.
func TestHandleComplete_ToolArgBytesTooLarge_Rejected(t *testing.T) {
	h := newHealthyHarness()
	big := strings.Repeat("A", (256<<10)+1) // > 256 KiB in one call's args
	h.openaiFake.resp = &provider.CompletionResponse{
		Model: "gpt-4o", Provider: "openai", FinishReason: "tool_calls",
		Usage:     provider.Usage{InputTokens: 10, OutputTokens: 5},
		ToolCalls: []provider.ToolCall{{ID: "c", Type: "function", Name: "f", Arguments: big}},
	}
	rr := doPost(t, h.server(), completePath, testBearer, completeBody())
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%q", rr.Code, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "tool_output_too_large" {
		t.Fatalf("code = %q, want tool_output_too_large", got)
	}
}

// A normal, small tool-call response passes and relays the calls (§18 passthrough).
func TestHandleComplete_ToolCallsWithinBounds_OK(t *testing.T) {
	h := newHealthyHarness()
	h.openaiFake.resp = &provider.CompletionResponse{
		Model: "gpt-4o", Provider: "openai", FinishReason: "tool_calls",
		Usage:     provider.Usage{InputTokens: 10, OutputTokens: 5},
		ToolCalls: []provider.ToolCall{{ID: "c1", Type: "function", Name: "read_file", Arguments: `{"path":"main.go"}`}},
	}
	rr := doPost(t, h.server(), completePath, testBearer, completeBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "read_file") {
		t.Errorf("expected the tool call relayed in the response: %s", rr.Body.String())
	}
}
