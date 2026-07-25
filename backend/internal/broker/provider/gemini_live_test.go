package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// gemini_live: an env-gated LIVE regression test against Google's real
// generateContent API (§32.1). It replays the ACTUAL shapes production sends —
// the CWE agent's pydantic tool schema (title + additionalProperties) and a
// multi-turn tool loop (assistant functionCall → tool result) — through the
// adapter and asserts a 200, so the two live 400s that shipped (schema-key
// rejection; empty functionResponse.name) cannot silently return.
//
// Skips unless GEMINI_LIVE_KEY is set (CI never calls a live model). Run:
//
//	GEMINI_LIVE_KEY=$GEMINI_API_KEY go test ./internal/broker/provider/ -run TestGeminiLive -v
func postGeminiLive(t *testing.T, key string, r gemRequest) (int, string) {
	t.Helper()
	body, _ := json.Marshal(r)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", key)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("live POST: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	return resp.StatusCode, string(b)
}

// realCWETool is the exact pydantic schema the CWE agent emits (title +
// additionalProperties:false) — the shape that produced the live 400.
func realCWETool() ToolDef {
	return ToolDef{Type: "function", Name: "check_injection", Parameters: map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"title":                "check_injection_args",
		"properties": map[string]any{
			"source_path": map[string]any{"description": "Path to source directory.", "title": "Source Path", "type": "string"},
		},
		"required": []any{"source_path"},
	}}
}

func TestGeminiLive_RealToolSchemaAccepted(t *testing.T) {
	key := os.Getenv("GEMINI_LIVE_KEY")
	if key == "" {
		t.Skip("set GEMINI_LIVE_KEY to run the live Gemini regression")
	}
	// Turn 1: real CWE tool schema + JSON response format (production shape).
	req := CompletionRequest{
		Model:          "gemini-2.5-flash",
		Messages:       []Message{{Role: "system", Content: "You are a code auditor."}, {Role: "user", Content: "Audit the source."}},
		Tools:          []ToolDef{realCWETool()},
		MaxTokens:      128,
		Temperature:    0,
		HasTemperature: true,
		ResponseFormat: "json_object",
	}
	if st, body := postGeminiLive(t, key, buildGeminiRequest(req)); st != 200 {
		t.Fatalf("turn-1 (real tool schema) status=%d body=%s", st, body)
	}
}

func TestGeminiLive_MultiTurnToolLoopAccepted(t *testing.T) {
	key := os.Getenv("GEMINI_LIVE_KEY")
	if key == "" {
		t.Skip("set GEMINI_LIVE_KEY to run the live Gemini regression")
	}
	// Turn 2: the multi-turn tool loop — built from the ACTUAL OpenAI wire the
	// agent SDK replays (tool_calls NESTED under "function", tool result keyed by
	// tool_call_id). This exercises #9b (nested parse → resolved
	// functionResponse.name) + #10 coalescing live; the production regression was
	// exactly this path 400ing with "function_response.name: Name cannot be empty".
	const wireMessages = `[
	  {"role":"user","content":"Scan for injection."},
	  {"role":"assistant","tool_calls":[
	    {"id":"c1","type":"function","function":{"name":"check_injection","arguments":"{\"source_path\":\".\"}"}},
	    {"id":"c2","type":"function","function":{"name":"check_injection","arguments":"{\"source_path\":\"x\"}"}}
	  ]},
	  {"role":"tool","tool_call_id":"c1","content":"no findings"},
	  {"role":"tool","tool_call_id":"c2","content":"no findings"}
	]`
	var msgs []Message
	if err := json.Unmarshal([]byte(wireMessages), &msgs); err != nil {
		t.Fatal(err)
	}
	req := CompletionRequest{
		Model:          "gemini-2.5-flash",
		Tools:          []ToolDef{realCWETool()},
		Messages:       msgs,
		MaxTokens:      128,
		Temperature:    0,
		HasTemperature: true,
	}
	if st, body := postGeminiLive(t, key, buildGeminiRequest(req)); st != 200 {
		t.Fatalf("turn-2 (multi-turn tool loop from wire) status=%d body=%s", st, body)
	}
}
