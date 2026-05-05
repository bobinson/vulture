package embedding

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const defaultBaseURL = "https://api.openai.com/v1"

// Client generates text embeddings via an OpenAI-compatible API.
// Supports OpenAI, Ollama (nomic-embed-text), and any OpenAI-compatible endpoint.
type Client struct {
	apiKey    string
	baseURL   string
	model     string
	local     bool // true when using a local endpoint (Ollama) that needs no API key
	http      *http.Client
	dimOnce   sync.Once
	dimension int // learned dimension from first successful Embed call

	// VLT-3890 hardening: bounded exponential-backoff retry on outbound
	// embedding-API calls. Transient failures (network errors, 5xx, 429
	// rate-limit) are retried up to retryMaxAttempts times with delay =
	// retryBaseDelay * 2^attempt. Non-retryable status codes (any other
	// 4xx) return immediately. Default 3 attempts × 100ms base.
	retryMaxAttempts int
	retryBaseDelay   time.Duration
}

const (
	defaultRetryMaxAttempts = 3
	defaultRetryBaseDelay   = 100 * time.Millisecond
)

// New creates an embedding client. Falls back gracefully if no API key is set
// and no local endpoint is configured.
func New() *Client {
	key := os.Getenv("OPENAI_API_KEY")
	baseURL := os.Getenv("VULTURE_EMBEDDING_URL")
	if baseURL == "" {
		// Fall back to OPENAI_BASE_URL (LM Studio, vLLM, etc.) before defaulting to OpenAI cloud.
		if altURL := os.Getenv("OPENAI_BASE_URL"); altURL != "" {
			baseURL = altURL
		} else {
			baseURL = defaultBaseURL
		}
	}
	model := os.Getenv("VULTURE_EMBEDDING_MODEL")
	if model == "" {
		model = "text-embedding-3-small"
	}

	// Detect local endpoints (Ollama, LM Studio, etc.) that don't need API keys.
	local := isLocalEndpoint(baseURL)

	return &Client{
		apiKey:           key,
		baseURL:          baseURL,
		model:            model,
		local:            local,
		http:             &http.Client{Timeout: 30 * time.Second},
		retryMaxAttempts: defaultRetryMaxAttempts,
		retryBaseDelay:   defaultRetryBaseDelay,
	}
}

// doWithRetry POSTs `body` to `url` (with optional Authorization) and
// retries the request on transient failures. Each attempt builds a fresh
// http.Request so the body is replayable. Returns the final response or
// the wrapped error from the last attempt.
//
// Retry policy:
//   - Network error (err != nil)               → retry
//   - HTTP 5xx (any 500-class status)          → retry
//   - HTTP 429 Too Many Requests               → retry
//   - HTTP 4xx other than 429 (client error)   → return immediately
//   - HTTP 2xx                                  → return immediately
//
// Backoff is `retryBaseDelay * 2^(attempt-1)` (e.g. 100ms, 200ms, 400ms).
func (c *Client) doWithRetry(url string, body []byte) (*http.Response, error) {
	maxAttempts := c.retryMaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = defaultRetryMaxAttempts
	}
	baseDelay := c.retryBaseDelay
	if baseDelay <= 0 {
		baseDelay = defaultRetryBaseDelay
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			time.Sleep(baseDelay << (attempt - 2)) // 100, 200, 400ms
		}

		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if c.apiKey != "" && !c.local {
			req.Header.Set("Authorization", "Bearer "+c.apiKey)
		}

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		// Retryable status: drain & close, record reason, loop.
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
			continue
		}
		// Success or non-retryable client error: return as-is for caller to handle.
		return resp, nil
	}
	return nil, fmt.Errorf("after %d attempts: %w", maxAttempts, lastErr)
}

// Available reports whether the embedding client is configured and ready.
// Returns true if an API key is set (cloud) OR a local endpoint is configured (Ollama).
func (c *Client) Available() bool {
	return c.apiKey != "" || c.local
}

// isLocalEndpoint detects local embedding services that don't require API keys.
// Uses proper URL parsing to only match the hostname, preventing bypass via
// URL path segments or hostname substrings (e.g., "localhost.evil.com").
func isLocalEndpoint(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "localhost" ||
		host == "127.0.0.1" ||
		host == "0.0.0.0" ||
		host == "::1" ||
		host == "host.docker.internal"
}

type embeddingRequest struct {
	Model string `json:"model"`
	Input string `json:"input"`
}

type embeddingResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
}

// Embed generates an embedding vector for the given text.
// Dimension depends on the model: 1536 for text-embedding-3-small, 768 for nomic-embed-text.
func (c *Client) Embed(text string) ([]float32, error) {
	if !c.Available() {
		return nil, fmt.Errorf("embedding client not configured: set OPENAI_API_KEY or VULTURE_EMBEDDING_URL for local Ollama")
	}

	body, err := json.Marshal(embeddingRequest{Model: c.model, Input: text})
	if err != nil {
		return nil, fmt.Errorf("marshal embedding request: %w", err)
	}

	resp, err := c.doWithRetry(c.baseURL+"/embeddings", body)
	if err != nil {
		return nil, fmt.Errorf("embedding API call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("embedding API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result embeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode embedding response: %w", err)
	}
	if len(result.Data) == 0 {
		return nil, fmt.Errorf("empty embedding response")
	}
	embedding := result.Data[0].Embedding
	if err := c.validateDimension(len(embedding)); err != nil {
		return nil, err
	}
	return embedding, nil
}

// validateDimension records the dimension on first call and returns an error
// if subsequent calls return a different dimension (likely model mismatch).
func (c *Client) validateDimension(dim int) error {
	c.dimOnce.Do(func() {
		c.dimension = dim
	})
	if dim != c.dimension {
		log.Printf("ERROR embedding_dimension_mismatch expected=%d got=%d model=%s", c.dimension, dim, c.model)
		return fmt.Errorf("embedding dimension mismatch: expected %d, got %d (model=%s)", c.dimension, dim, c.model)
	}
	return nil
}

// EmbedBatch generates embeddings for multiple texts in a single API call.
func (c *Client) EmbedBatch(texts []string) ([][]float32, error) {
	if !c.Available() {
		return nil, fmt.Errorf("embedding client not configured: set OPENAI_API_KEY or VULTURE_EMBEDDING_URL for local Ollama")
	}

	type batchReq struct {
		Model string   `json:"model"`
		Input []string `json:"input"`
	}
	body, err := json.Marshal(batchReq{Model: c.model, Input: texts})
	if err != nil {
		return nil, fmt.Errorf("marshal batch request: %w", err)
	}

	resp, err := c.doWithRetry(c.baseURL+"/embeddings", body)
	if err != nil {
		return nil, fmt.Errorf("batch embedding API call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("batch embedding API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result embeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode batch response: %w", err)
	}
	embeddings := make([][]float32, len(result.Data))
	for i, d := range result.Data {
		if err := c.validateDimension(len(d.Embedding)); err != nil {
			return nil, err
		}
		embeddings[i] = d.Embedding
	}
	return embeddings, nil
}
