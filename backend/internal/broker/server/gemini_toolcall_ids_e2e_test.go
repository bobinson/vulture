package server_test

// End-to-end broker → Gemini multi-turn tool loop (stub upstream). The OpenAI
// Agents SDK tracks every completed tool-call id for the WHOLE run and raises
// "Model reused a completed tool call ID for a different invocation" when a
// later turn repeats one. Gemini's native wire gives the broker no id it has
// to keep, so the broker mints them — and they must be unique across turns,
// not just within one response. The same ids key the request-side reverse map
// tool_call_id → functionResponse.name, so a repeated id also mislabels which
// tool produced a result on the next upstream request.
//
// Same harness shape as lmstudio_broker_e2e_test.go (full server.Handler()
// pipeline, real provider adapter), with an httptest Gemini standing in for
// the live API so it runs untagged in CI.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/token"
)

const geminiLoopModel = "gemini-2.5-flash"

// geminiLoopStub serves a scripted generateContent reply per turn and records
// every upstream request body so a test can read what the broker sent.
type geminiLoopStub struct {
	mu       sync.Mutex
	replies  []string
	requests []map[string]any
}

func (s *geminiLoopStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	s.mu.Lock()
	turn := len(s.requests)
	s.requests = append(s.requests, body)
	s.mu.Unlock()
	if turn >= len(s.replies) {
		http.Error(w, `{"error":{"message":"unscripted turn"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, s.replies[turn])
}

// functionResponseNames lists functionResponse.name, in order, across the
// contents of one recorded upstream request.
func functionResponseNames(req map[string]any) []string {
	var names []string
	contents, _ := req["contents"].([]any)
	for _, c := range contents {
		cm, _ := c.(map[string]any)
		parts, _ := cm["parts"].([]any)
		for _, p := range parts {
			pm, _ := p.(map[string]any)
			if fr, ok := pm["functionResponse"].(map[string]any); ok {
				name, _ := fr["name"].(string)
				names = append(names, name)
			}
		}
	}
	return names
}

// wireToolCalls decodes choices[0].message.tool_calls from a broker response.
func wireToolCalls(t *testing.T, rr *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	var out struct {
		Choices []struct {
			Message struct {
				ToolCalls []map[string]any `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode broker response: %v (%s)", err, rr.Body.String())
	}
	if len(out.Choices) == 0 {
		t.Fatalf("broker response has no choices: %s", rr.Body.String())
	}
	return out.Choices[0].Message.ToolCalls
}

func toolCallIDName(t *testing.T, tc map[string]any) (string, string) {
	t.Helper()
	id, _ := tc["id"].(string)
	fn, _ := tc["function"].(map[string]any)
	name, _ := fn["name"].(string)
	if id == "" || name == "" {
		t.Fatalf("tool call missing id or name: %v", tc)
	}
	return id, name
}

// newGeminiLoopBroker wires the full broker to the stub through the real
// native Gemini adapter, with a token scoped to the Gemini model.
func newGeminiLoopBroker(t *testing.T, upstreamURL string) *harness {
	t.Helper()
	h := newHealthyHarness()
	h.verifier.claims = &token.Claims{
		Subject: "run-gemini-loop", TenantID: "local", Scope: []string{"scan:" + geminiLoopModel},
		BudgetRef: "budget-local", Region: "us", JTI: "jti-gemini-loop", KID: "kid-1", ExpiresAt: 1 << 40,
	}
	h.selector.sel = &egress.ModelSelection{Model: geminiLoopModel}
	h.ssrf.target = &egress.PinnedTarget{URL: upstreamURL, Provider: "gemini"}
	h.adapters = map[string]provider.Adapter{"gemini": provider.NewGeminiAdapter(&http.Client{})}
	return h
}

func geminiLoopTools() []map[string]any {
	tool := func(name string) map[string]any {
		return map[string]any{"type": "function", "function": map[string]any{
			"name": name, "description": name,
			"parameters": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}}},
		}}
	}
	return []map[string]any{tool("list_files"), tool("read_file"), tool("grep_code")}
}

// TestE2E_Broker_Gemini_ToolCallIDsUniqueAcrossTurns drives the loop the agent
// SDK runs: turn 1 the model calls list_files; turn 2 it calls read_file and
// grep_code in parallel; turn 3 it answers. Every id the broker hands back
// must be distinct across the run, and each functionResponse the broker sends
// upstream must name the tool that actually produced that result.
func TestE2E_Broker_Gemini_ToolCallIDsUniqueAcrossTurns(t *testing.T) {
	stub := &geminiLoopStub{replies: []string{
		`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"list_files","args":{"path":"."}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":40,"candidatesTokenCount":5}}`,
		`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"read_file","args":{"path":"main.go"}}},{"functionCall":{"name":"grep_code","args":{"path":"exec"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":60,"candidatesTokenCount":8}}`,
		`{"candidates":[{"content":{"role":"model","parts":[{"text":"[]"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":90,"candidatesTokenCount":2}}`,
	}}
	upstream := httptest.NewServer(stub)
	defer upstream.Close()
	srv := newGeminiLoopBroker(t, upstream.URL).server()

	messages := []map[string]any{
		{"role": "system", "content": "You are a code auditor."},
		{"role": "user", "content": "Audit the source root."},
	}
	results := map[string]string{"list_files": "main.go", "read_file": "package main", "grep_code": "main.go:3 exec.Command"}
	seen := map[string]string{} // id → tool name, across the whole run
	for turn := 1; turn <= 2; turn++ {
		body := completeBody()
		body["model_hint"] = geminiLoopModel
		body["request_id"] = "req-gemini-loop" // the SDK may reuse one request id per run
		body["messages"] = messages
		body["tools"] = geminiLoopTools()
		rr := doPost(t, srv, completePath, testBearer, body)
		if rr.Code != http.StatusOK {
			t.Fatalf("turn %d status=%d body=%s", turn, rr.Code, rr.Body.String())
		}
		calls := wireToolCalls(t, rr)
		if len(calls) == 0 {
			t.Fatalf("turn %d: no tool calls returned: %s", turn, rr.Body.String())
		}
		var replay []map[string]any
		var toolMsgs []map[string]any
		for _, tc := range calls {
			id, name := toolCallIDName(t, tc)
			if prev, dup := seen[id]; dup {
				t.Errorf("turn %d: tool call id %q for %s reuses the id already issued for %s — the agent SDK rejects this", turn, id, name, prev)
			}
			seen[id] = name
			replay = append(replay, tc)
			toolMsgs = append(toolMsgs, map[string]any{"role": "tool", "tool_call_id": id, "content": results[name]})
		}
		messages = append(messages, map[string]any{"role": "assistant", "content": nil, "tool_calls": replay})
		messages = append(messages, toolMsgs...)
	}

	body := completeBody()
	body["model_hint"] = geminiLoopModel
	body["request_id"] = "req-gemini-loop"
	body["messages"] = messages
	body["tools"] = geminiLoopTools()
	if rr := doPost(t, srv, completePath, testBearer, body); rr.Code != http.StatusOK {
		t.Fatalf("turn 3 status=%d body=%s", rr.Code, rr.Body.String())
	}

	if len(stub.requests) != 3 {
		t.Fatalf("upstream saw %d requests, want 3", len(stub.requests))
	}
	if got := functionResponseNames(stub.requests[1]); strings.Join(got, ",") != "list_files" {
		t.Errorf("turn 2 upstream functionResponse names = %v, want [list_files]", got)
	}
	want := "list_files,read_file,grep_code"
	if got := functionResponseNames(stub.requests[2]); strings.Join(got, ",") != want {
		t.Errorf("turn 3 upstream functionResponse names = %v, want [%s] (each result must name the tool that produced it)", got, want)
	}
}
