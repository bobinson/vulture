package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vulture/backend/internal/config"
)

// LLMHealthHandler aggregates one running agent's /health.llm sub-object
// and serves it on /api/llm/health. Result is cached for
// VULTURE_LLM_HEALTH_CACHE_TTL seconds (default 5) to absorb UI polling.
//
// Implements feature 0039 Phase 3.
type LLMHealthHandler struct {
	agents   map[string]config.AgentConfig
	mu       sync.Mutex
	cache    *llmHealthCacheEntry
	cacheTTL time.Duration
}

type llmHealthCacheEntry struct {
	value    LLMHealthResponse
	cachedAt time.Time
}

// LLMHealthResponse is the JSON shape returned by /api/llm/health.
// Fields mirror shared.llm.health.LLMHealthStatus exactly.
type LLMHealthResponse struct {
	Provider  string                 `json:"provider"`
	Endpoint  string                 `json:"endpoint"`
	Model     string                 `json:"model"`
	Reachable bool                   `json:"reachable"`
	Error     string                 `json:"error,omitempty"`
	Detail    map[string]interface{} `json:"detail,omitempty"`
	Message   string                 `json:"message"`
}

// agentHealthBody is the shape of GET /health on each agent.
// `LLM` is the LLMHealthStatus.as_dict() from shared.llm.health.
type agentHealthBody struct {
	Status     string             `json:"status"`
	Agent      string             `json:"agent"`
	LLM        *LLMHealthResponse `json:"llm,omitempty"`
	LLMMessage string             `json:"llm_message,omitempty"`
}

// NewLLMHealthHandler constructs a handler that aggregates LLM health from
// the configured agents.
func NewLLMHealthHandler(agents map[string]config.AgentConfig) *LLMHealthHandler {
	ttl := 5 * time.Second
	if v, err := strconv.Atoi(os.Getenv("VULTURE_LLM_HEALTH_CACHE_TTL")); err == nil && v > 0 {
		ttl = time.Duration(v) * time.Second
	}
	return &LLMHealthHandler{agents: agents, cacheTTL: ttl}
}

func (h *LLMHealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	resp, err := h.Get(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway,
			fmt.Sprintf("could not reach any agent: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Get returns the cached LLM health response, refreshing on cache miss.
// Exported so other handlers (audit_handler.Create per Phase 5) can read
// the same cached value without re-probing.
func (h *LLMHealthHandler) Get(ctx context.Context) (LLMHealthResponse, error) {
	h.mu.Lock()
	if h.cache != nil && time.Since(h.cache.cachedAt) < h.cacheTTL {
		v := h.cache.value
		h.mu.Unlock()
		return v, nil
	}
	h.mu.Unlock()

	v, err := h.fetchFromAnyAgent(ctx)
	if err != nil {
		return LLMHealthResponse{}, err
	}

	h.mu.Lock()
	h.cache = &llmHealthCacheEntry{value: v, cachedAt: time.Now()}
	h.mu.Unlock()
	return v, nil
}

// fetchFromAnyAgent queries each registered agent's /health in turn and
// returns the first response with a non-nil llm sub-object. All agents
// share the same env so the answer is identical; we just need one to be
// alive AND have the new /health shape.
func (h *LLMHealthHandler) fetchFromAnyAgent(ctx context.Context) (LLMHealthResponse, error) {
	client := http.Client{Timeout: 4 * time.Second}
	var lastErr error
	for _, ag := range h.agents {
		if ag.URL == "" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ag.URL+"/health", nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body := decodeAgentHealth(resp)
		_ = resp.Body.Close()
		if body == nil {
			continue
		}
		if body.LLM == nil {
			lastErr = fmt.Errorf("agent %s /health has no llm field (agent likely older than 0039)", ag.Name)
			continue
		}
		v := *body.LLM
		v.Message = body.LLMMessage
		return v, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no agents configured")
	}
	return LLMHealthResponse{}, lastErr
}

// decodeAgentHealth parses an agent /health response. Returns nil on any
// status/decode failure (caller treats nil as "skip this agent").
func decodeAgentHealth(resp *http.Response) *agentHealthBody {
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var body agentHealthBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}
	// Some agents may report status="healthy" while others use status="ok"
	// — accept any non-empty status field.
	if strings.TrimSpace(body.Status) == "" {
		return nil
	}
	return &body
}
