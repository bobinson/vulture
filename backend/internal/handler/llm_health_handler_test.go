package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vulture/backend/internal/config"
)

// helper: spin up a fake agent /health server that returns the given JSON.
func newFakeAgent(t *testing.T, body interface{}, calls *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		if calls != nil {
			atomic.AddInt32(calls, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func TestLLMHealth_HappyPath(t *testing.T) {
	agentBody := map[string]any{
		"status": "healthy",
		"agent":  "chaos",
		"llm": map[string]any{
			"provider":  "lmstudio",
			"endpoint":  "http://localhost:1234/v1",
			"model":     "qwen3:8b",
			"reachable": true,
			"error":     "",
		},
		"llm_message": "LLM ready: lmstudio (qwen3:8b) at http://localhost:1234/v1",
	}
	srv := newFakeAgent(t, agentBody, nil)
	defer srv.Close()

	agents := map[string]config.AgentConfig{
		"chaos": {Name: "chaos", Type: "chaos", URL: srv.URL},
	}
	h := NewLLMHealthHandler(agents)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/llm/health", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp LLMHealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Reachable || resp.Provider != "lmstudio" || resp.Model != "qwen3:8b" {
		t.Errorf("unexpected response: %+v", resp)
	}
	if resp.Message != "LLM ready: lmstudio (qwen3:8b) at http://localhost:1234/v1" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
}

func TestLLMHealth_DegradedPath(t *testing.T) {
	agentBody := map[string]any{
		"status": "healthy",
		"agent":  "chaos",
		"llm": map[string]any{
			"provider":  "lmstudio",
			"endpoint":  "http://localhost:1234/v1",
			"model":     "qwen3:8b",
			"reachable": false,
			"error":     "connection refused at http://localhost:1234/v1",
		},
		"llm_message": "LLM unavailable: lmstudio (qwen3:8b) at http://localhost:1234/v1 — connection refused at http://localhost:1234/v1. Audit will run skills-only.",
	}
	srv := newFakeAgent(t, agentBody, nil)
	defer srv.Close()

	h := NewLLMHealthHandler(map[string]config.AgentConfig{
		"chaos": {Name: "chaos", Type: "chaos", URL: srv.URL},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/llm/health", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp LLMHealthResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Reachable {
		t.Error("expected reachable=false")
	}
	if !contains(resp.Message, "Audit will run skills-only") {
		t.Errorf("expected canonical degraded suffix; got: %q", resp.Message)
	}
}

func TestLLMHealth_CacheHits(t *testing.T) {
	var calls int32
	agentBody := map[string]any{
		"status": "healthy", "agent": "chaos",
		"llm": map[string]any{
			"provider": "lmstudio", "endpoint": "x", "model": "y", "reachable": true,
		},
		"llm_message": "ok",
	}
	srv := newFakeAgent(t, agentBody, &calls)
	defer srv.Close()

	h := NewLLMHealthHandler(map[string]config.AgentConfig{
		"chaos": {Name: "chaos", Type: "chaos", URL: srv.URL},
	})

	for i := 0; i < 50; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/llm/health", nil)
		h.ServeHTTP(rec, req)
	}

	if got := atomic.LoadInt32(&calls); got > 1 {
		t.Errorf("expected cache to absorb 50 calls; agent saw %d", got)
	}
}

func TestLLMHealth_CacheExpires(t *testing.T) {
	var calls int32
	agentBody := map[string]any{
		"status": "healthy", "agent": "chaos",
		"llm": map[string]any{
			"provider": "lmstudio", "endpoint": "x", "model": "y", "reachable": true,
		},
		"llm_message": "ok",
	}
	srv := newFakeAgent(t, agentBody, &calls)
	defer srv.Close()

	h := NewLLMHealthHandler(map[string]config.AgentConfig{
		"chaos": {Name: "chaos", Type: "chaos", URL: srv.URL},
	})
	h.cacheTTL = 50 * time.Millisecond

	_, _ = h.Get(context.Background())
	time.Sleep(70 * time.Millisecond)
	_, _ = h.Get(context.Background())

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected 2 underlying calls (one before, one after expiry); got %d", got)
	}
}

func TestLLMHealth_NoAgents(t *testing.T) {
	h := NewLLMHealthHandler(map[string]config.AgentConfig{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/llm/health", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502 when no agents configured, got %d", rec.Code)
	}
}

func TestLLMHealth_FallsThroughToNextAgent(t *testing.T) {
	// First agent returns no llm key (older agent); second has new shape.
	dead := newFakeAgent(t, map[string]any{
		"status": "healthy", "agent": "old-agent",
	}, nil)
	defer dead.Close()
	live := newFakeAgent(t, map[string]any{
		"status": "healthy", "agent": "new-agent",
		"llm": map[string]any{
			"provider": "ollama", "endpoint": "http://localhost:11434",
			"model": "qwen3:1.7b", "reachable": true,
		},
		"llm_message": "LLM ready: ollama (qwen3:1.7b) at http://localhost:11434",
	}, nil)
	defer live.Close()

	h := NewLLMHealthHandler(map[string]config.AgentConfig{
		"old": {Name: "old", Type: "old", URL: dead.URL},
		"new": {Name: "new", Type: "new", URL: live.URL},
	})

	resp, err := h.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Provider != "ollama" {
		t.Errorf("expected fallthrough to new agent; got provider=%s", resp.Provider)
	}
}

func TestLLMHealth_RejectsNonGet(t *testing.T) {
	h := NewLLMHealthHandler(map[string]config.AgentConfig{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/llm/health", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
