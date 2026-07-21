package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// postRaw sends a raw OpenAI body + explicit headers (no translation), so the
// genuine wire contract (§26 C1) is exercised directly.
func postRaw(t *testing.T, h *harness, path, bearer string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatalf("encode: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.server().Handler().ServeHTTP(rr, req)
	return rr
}

func openaiChatBody() map[string]any {
	return map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]any{{"role": "user", "content": "hello"}},
	}
}

func vultureHeaders() map[string]string {
	return map[string]string{"X-Vulture-Task-Type": "scan", "X-Vulture-Request-Id": "req-1"}
}

// C1: a genuine OpenAI Chat-Completions request (model+messages body, metadata
// in X-Vulture headers) succeeds and returns a chat.completion object.
func TestOpenAIWire_ChatCompletionRoundTrip(t *testing.T) {
	h := newHealthyHarness()
	rr := postRaw(t, h, completePath, testBearer, openaiChatBody(), vultureHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if raw["object"] != "chat.completion" {
		t.Errorf("object = %v, want chat.completion", raw["object"])
	}
	if _, ok := raw["choices"].([]any); !ok {
		t.Errorf("response has no choices array: %q", rr.Body.String())
	}
	// task_type from the header must have driven the scope check for gpt-4o.
	if len(h.ssrf.providers) == 0 {
		t.Error("pipeline did not reach egress — header-derived task_type may not have scoped correctly")
	}
}

// C1/§5: missing required X-Vulture metadata headers → invalid_request.
func TestOpenAIWire_MissingMetadataHeaders_Rejected(t *testing.T) {
	h := newHealthyHarness()
	rr := postRaw(t, h, completePath, testBearer, openaiChatBody(), nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (missing X-Vulture headers); body=%q", rr.Code, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "invalid_request" {
		t.Errorf("code = %q, want invalid_request", got)
	}
}

// M6/§5: stream:true is rejected (not silently downgraded).
func TestOpenAIWire_StreamRejected(t *testing.T) {
	h := newHealthyHarness()
	body := openaiChatBody()
	body["stream"] = true
	rr := postRaw(t, h, completePath, testBearer, body, vultureHeaders())
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (stream unsupported); body=%q", rr.Code, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "invalid_request" {
		t.Errorf("code = %q, want invalid_request", got)
	}
	if h.openaiFake.completeReq != nil {
		t.Error("a stream request reached the provider; it must be rejected before egress")
	}
}

// H4/§5: an over-size body → request_too_large, before any provider call.
func TestOpenAIWire_OversizeBody_Rejected(t *testing.T) {
	h := newHealthyHarness()
	big := strings.Repeat("A", (1<<20)+1024) // > 1 MiB cap
	body := openaiChatBody()
	body["messages"] = []map[string]any{{"role": "user", "content": big}}
	rr := postRaw(t, h, completePath, testBearer, body, vultureHeaders())
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%q", rr.Code, truncate(rr.Body.String()))
	}
	if got := decodeErr(t, rr).Error.Code; got != "request_too_large" {
		t.Errorf("code = %q, want request_too_large", got)
	}
}

func truncate(s string) string {
	if len(s) > 120 {
		return s[:120]
	}
	return s
}
