package handler

import (
	"net/http"
	"sync"
	"time"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
)

type AgentHandler struct {
	agents   map[string]config.AgentConfig
	readOnly bool
}

func NewAgentHandler(agents map[string]config.AgentConfig) *AgentHandler {
	return &AgentHandler{agents: agents}
}

// SetReadOnly enables read-only mode. When true, List returns an empty
// agent list without probing agent health endpoints.
func (h *AgentHandler) SetReadOnly(v bool) { h.readOnly = v }

func (h *AgentHandler) List(w http.ResponseWriter, _ *http.Request) {
	if h.readOnly {
		writeJSON(w, http.StatusOK, []model.AgentInfo{})
		return
	}

	type result struct {
		key    string
		status string
	}

	// Run health checks concurrently with a 2s timeout per agent.
	var wg sync.WaitGroup
	ch := make(chan result, len(h.agents))
	for key, a := range h.agents {
		wg.Add(1)
		go func(k string, url string) {
			defer wg.Done()
			ch <- result{key: k, status: checkAgentHealth(url)}
		}(key, a.URL)
	}
	wg.Wait()
	close(ch)

	statusMap := make(map[string]string, len(h.agents))
	for r := range ch {
		statusMap[r.key] = r.status
	}

	infos := make([]model.AgentInfo, 0, len(h.agents))
	for key, a := range h.agents {
		infos = append(infos, model.AgentInfo{
			ID:     key,
			Name:   a.Name,
			Type:   a.Type,
			Status: statusMap[key],
		})
	}
	writeJSON(w, http.StatusOK, infos)
}

// healthClient is a shared HTTP client for agent health checks, avoiding
// per-call allocation.
var healthClient = &http.Client{Timeout: 2 * time.Second}

// checkAgentHealth probes the agent's /health endpoint.
// Returns "healthy", "unhealthy", or "unknown".
func checkAgentHealth(baseURL string) string {
	if baseURL == "" {
		return "unknown"
	}
	resp, err := healthClient.Get(baseURL + "/health")
	if err != nil {
		return "unhealthy"
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return "healthy"
	}
	return "unhealthy"
}
