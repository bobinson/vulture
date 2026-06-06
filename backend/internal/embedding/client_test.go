package embedding

import (
	"sync/atomic"
	"time"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNew_DefaultValues(t *testing.T) {
	// Clear env to test defaults
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("VULTURE_EMBEDDING_URL", "")
	t.Setenv("VULTURE_EMBEDDING_MODEL", "")

	c := New()
	if c.apiKey != "" {
		t.Errorf("expected empty api key, got %q", c.apiKey)
	}
	if c.baseURL != "https://api.openai.com/v1" {
		t.Errorf("expected default base URL, got %q", c.baseURL)
	}
	if c.model != "text-embedding-3-small" {
		t.Errorf("expected default model, got %q", c.model)
	}
}

func TestNew_CustomEnvVars(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test-123")
	t.Setenv("VULTURE_EMBEDDING_URL", "http://custom:8080/v1")
	t.Setenv("VULTURE_EMBEDDING_MODEL", "text-embedding-ada-002")

	c := New()
	if c.apiKey != "sk-test-123" {
		t.Errorf("expected custom api key, got %q", c.apiKey)
	}
	if c.baseURL != "http://custom:8080/v1" {
		t.Errorf("expected custom base URL, got %q", c.baseURL)
	}
	if c.model != "text-embedding-ada-002" {
		t.Errorf("expected custom model, got %q", c.model)
	}
}

func TestAvailable_WithKey(t *testing.T) {
	c := &Client{apiKey: "sk-test"}
	if !c.Available() {
		t.Error("expected Available()=true with API key")
	}
}

func TestAvailable_WithoutKey(t *testing.T) {
	c := &Client{apiKey: ""}
	if c.Available() {
		t.Error("expected Available()=false without API key and non-local URL")
	}
}

func TestAvailable_LocalOllama(t *testing.T) {
	c := &Client{apiKey: "", local: true}
	if !c.Available() {
		t.Error("expected Available()=true for local Ollama endpoint")
	}
}

func TestIsLocalEndpoint(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://localhost:11434/v1", true},
		{"http://127.0.0.1:11434/v1", true},
		{"http://0.0.0.0:11434/v1", true},
		{"http://[::1]:11434/v1", true},
		{"http://LOCALHOST:11434/v1", true},
		{"https://api.openai.com/v1", false},
		{"http://my-server.com:11434/v1", false},
		// Security: must NOT match localhost in URL path or as hostname substring
		{"https://evil.com/localhost/proxy", false},
		{"https://localhost.evil.com:11434/v1", false},
		// userinfo@host: hostname is 127.0.0.1, so this IS local
		{"https://evil.com@127.0.0.1:11434/v1", true},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := isLocalEndpoint(tt.url)
			if got != tt.want {
				t.Errorf("isLocalEndpoint(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestNew_OllamaLocalDetection(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("VULTURE_EMBEDDING_URL", "http://localhost:11434/v1")
	t.Setenv("VULTURE_EMBEDDING_MODEL", "nomic-embed-text")

	c := New()
	if !c.Available() {
		t.Error("expected Available()=true for Ollama local endpoint")
	}
	if c.model != "nomic-embed-text" {
		t.Errorf("expected model=nomic-embed-text, got %q", c.model)
	}
	if !c.local {
		t.Error("expected local=true for localhost URL")
	}
}

func TestEmbed_Success(t *testing.T) {
	expectedVec := []float32{0.1, 0.2, 0.3}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/embeddings") {
			t.Errorf("expected /embeddings path, got %s", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer sk-test" {
			t.Errorf("expected Bearer sk-test, got %q", auth)
		}

		var req embeddingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}
		if req.Model != "test-model" {
			t.Errorf("expected model=test-model, got %q", req.Model)
		}

		resp := embeddingResponse{
			Data: []struct {
				Embedding []float32 `json:"embedding"`
			}{
				{Embedding: expectedVec},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := &Client{
		apiKey:  "sk-test",
		baseURL: server.URL,
		model:   "test-model",
		http:    server.Client(),
	}

	vec, err := c.Embed("test text")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vec) != 3 {
		t.Fatalf("expected 3 dimensions, got %d", len(vec))
	}
	for i, v := range vec {
		if v != expectedVec[i] {
			t.Errorf("vec[%d]=%f, want %f", i, v, expectedVec[i])
		}
	}
}

func TestEmbed_Unavailable(t *testing.T) {
	c := &Client{apiKey: ""}

	_, err := c.Embed("text")
	if err == nil {
		t.Fatal("expected error when client unavailable")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("expected 'not configured' error, got %v", err)
	}
}

func TestEmbed_OllamaNoAuthHeader(t *testing.T) {
	expectedVec := []float32{0.1, 0.2, 0.3}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify no Authorization header is sent for local mode
		auth := r.Header.Get("Authorization")
		if auth != "" {
			t.Errorf("expected no Authorization header for Ollama, got %q", auth)
		}

		resp := embeddingResponse{
			Data: []struct {
				Embedding []float32 `json:"embedding"`
			}{
				{Embedding: expectedVec},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := &Client{
		apiKey:  "",
		baseURL: server.URL,
		model:   "nomic-embed-text",
		local:   true,
		http:    server.Client(),
	}

	vec, err := c.Embed("test text")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vec) != 3 {
		t.Fatalf("expected 3 dimensions, got %d", len(vec))
	}
}

func TestEmbed_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate limited"}`))
	}))
	defer server.Close()

	c := &Client{
		apiKey:  "sk-test",
		baseURL: server.URL,
		model:   "test-model",
		http:    server.Client(),
	}

	_, err := c.Embed("text")
	if err == nil {
		t.Fatal("expected error on API error response")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("expected status code in error, got %v", err)
	}
}

func TestEmbed_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := embeddingResponse{Data: nil}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := &Client{
		apiKey:  "sk-test",
		baseURL: server.URL,
		model:   "test-model",
		http:    server.Client(),
	}

	_, err := c.Embed("text")
	if err == nil {
		t.Fatal("expected error on empty response")
	}
	if !strings.Contains(err.Error(), "empty embedding") {
		t.Errorf("expected 'empty embedding' error, got %v", err)
	}
}

func TestEmbed_InvalidResponseJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	c := &Client{
		apiKey:  "sk-test",
		baseURL: server.URL,
		model:   "test-model",
		http:    server.Client(),
	}

	_, err := c.Embed("text")
	if err == nil {
		t.Fatal("expected error on invalid JSON response")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("expected decode error, got %v", err)
	}
}

func TestEmbedBatch_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model string   `json:"model"`
			Input []string `json:"input"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		if len(req.Input) != 2 {
			t.Errorf("expected 2 inputs, got %d", len(req.Input))
		}

		resp := embeddingResponse{
			Data: []struct {
				Embedding []float32 `json:"embedding"`
			}{
				{Embedding: []float32{0.1, 0.2}},
				{Embedding: []float32{0.3, 0.4}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := &Client{
		apiKey:  "sk-test",
		baseURL: server.URL,
		model:   "test-model",
		http:    server.Client(),
	}

	vecs, err := c.EmbedBatch([]string{"text1", "text2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vecs) != 2 {
		t.Fatalf("expected 2 vectors, got %d", len(vecs))
	}
	if len(vecs[0]) != 2 || len(vecs[1]) != 2 {
		t.Errorf("expected 2 dimensions each, got %d and %d", len(vecs[0]), len(vecs[1]))
	}
}

func TestEmbedBatch_Unavailable(t *testing.T) {
	c := &Client{apiKey: ""}

	_, err := c.EmbedBatch([]string{"text"})
	if err == nil {
		t.Fatal("expected error when client unavailable")
	}
}

func TestEmbedBatch_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
	}))
	defer server.Close()

	c := &Client{
		apiKey:  "sk-test",
		baseURL: server.URL,
		model:   "test-model",
		http:    server.Client(),
	}

	_, err := c.EmbedBatch([]string{"text"})
	if err == nil {
		t.Fatal("expected error on API error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected status code in error, got %v", err)
	}
}

func TestEmbedBatch_InvalidResponseJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`not json`))
	}))
	defer server.Close()

	c := &Client{
		apiKey:  "sk-test",
		baseURL: server.URL,
		model:   "test-model",
		http:    server.Client(),
	}

	_, err := c.EmbedBatch([]string{"text"})
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

// --- VLT-3890 hardening: bounded retry+backoff on outbound HTTP --------------
//
// Embed and EmbedBatch send HTTPS requests to OpenAI/Ollama embedding
// endpoints. The previous implementation called c.http.Do(req) once and
// surfaced any error to callers, including transient failures (network
// blips, 5xx, rate-limit 429). These tests pin the contract that
// transient errors are automatically retried with bounded exponential
// backoff before the final error is returned.

func TestEmbed_RetriesOn503ThenSucceeds(t *testing.T) {
	var attempts int32
	expectedVec := []float32{0.1, 0.2}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(embeddingResponse{
			Data: []struct {
				Embedding []float32 `json:"embedding"`
			}{{Embedding: expectedVec}},
		})
	}))
	defer server.Close()

	c := &Client{apiKey: "sk-test", baseURL: server.URL, model: "m", http: server.Client()}
	c.retryBaseDelay = time.Millisecond // keep test fast

	vec, err := c.Embed("text")
	if err != nil {
		t.Fatalf("unexpected error after retries: %v", err)
	}
	if len(vec) != 2 {
		t.Fatalf("expected 2 dims, got %d", len(vec))
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("expected 3 attempts (2 fail + 1 success), got %d", got)
	}
}

func TestEmbed_RetriesOn429ThenSucceeds(t *testing.T) {
	var attempts int32
	expectedVec := []float32{0.5}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(embeddingResponse{
			Data: []struct {
				Embedding []float32 `json:"embedding"`
			}{{Embedding: expectedVec}},
		})
	}))
	defer server.Close()

	c := &Client{apiKey: "sk-test", baseURL: server.URL, model: "m", http: server.Client()}
	c.retryBaseDelay = time.Millisecond

	if _, err := c.Embed("text"); err != nil {
		t.Fatalf("expected retry on 429 to succeed, got %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Fatalf("expected 2 attempts on 429-then-200, got %d", got)
	}
}

func TestEmbed_DoesNotRetryOn400(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	c := &Client{apiKey: "sk-test", baseURL: server.URL, model: "m", http: server.Client()}
	c.retryBaseDelay = time.Millisecond

	_, err := c.Embed("text")
	if err == nil {
		t.Fatal("expected error on 400")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("expected exactly 1 attempt on 400 (not retryable), got %d", got)
	}
}

func TestEmbed_GivesUpAfterMaxAttempts(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := &Client{apiKey: "sk-test", baseURL: server.URL, model: "m", http: server.Client()}
	c.retryBaseDelay = time.Millisecond

	_, err := c.Embed("text")
	if err == nil {
		t.Fatal("expected final error after all retries fail")
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("expected 3 total attempts (max), got %d", got)
	}
}

func TestEmbedBatch_RetriesOn503(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(embeddingResponse{
			Data: []struct {
				Embedding []float32 `json:"embedding"`
			}{{Embedding: []float32{0.1}}, {Embedding: []float32{0.2}}},
		})
	}))
	defer server.Close()

	c := &Client{apiKey: "sk-test", baseURL: server.URL, model: "m", http: server.Client()}
	c.retryBaseDelay = time.Millisecond

	vecs, err := c.EmbedBatch([]string{"a", "b"})
	if err != nil {
		t.Fatalf("expected EmbedBatch to retry on 503: %v", err)
	}
	if len(vecs) != 2 {
		t.Fatalf("expected 2 vectors back, got %d", len(vecs))
	}
}
