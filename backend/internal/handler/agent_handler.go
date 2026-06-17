package handler

import (
	"net/http"
	"sync"
	"time"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/pkg/agentregistry"
	"github.com/vulture/backend/pkg/pluginregistry"
)

type AgentHandler struct {
	agents   map[string]config.AgentConfig
	readOnly bool
	// G1: when wired, enabled registry plugins (e.g. semgrep) are surfaced in
	// /api/agents alongside the built-in agents. nil-safe — when unset the
	// handler behaves exactly as before (built-ins only).
	reg       pluginregistry.Registry
	pluginURL func(pluginregistry.Plugin) string
}

func NewAgentHandler(agents map[string]config.AgentConfig) *AgentHandler {
	return &AgentHandler{agents: agents}
}

// SetReadOnly enables read-only mode. When true, List returns an empty
// agent list without probing agent health endpoints.
func (h *AgentHandler) SetReadOnly(v bool) { h.readOnly = v }

// SetPluginRegistry makes /api/agents registry-aware (G1): enabled plugins not
// already present as a built-in agent are appended to the listing. urlFor
// resolves a plugin's base URL for the health probe (typically
// stagerouter.NewURLResolver(cfg.Agents).Resolve).
func (h *AgentHandler) SetPluginRegistry(reg pluginregistry.Registry, urlFor func(pluginregistry.Plugin) string) {
	h.reg = reg
	h.pluginURL = urlFor
}

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

	// Index registry entries by Type so we can flag Optional agents on
	// the response. The frontend uses Optional to badge opt-in agents
	// in the audit type selector.
	optional := make(map[string]bool, len(agentregistry.AllAgents))
	for _, e := range agentregistry.AllAgents {
		if e.Optional {
			optional[e.Type] = true
		}
	}

	infos := make([]model.AgentInfo, 0, len(h.agents))
	// Built-in types already listed — used to dedupe registry plugins, which
	// also carry the in-tree agents as virtual plugins.
	builtinTypes := make(map[string]bool, len(h.agents))
	for key, a := range h.agents {
		builtinTypes[a.Type] = true
		infos = append(infos, model.AgentInfo{
			ID:       key,
			Name:     a.Name,
			Type:     a.Type,
			Status:   statusMap[key],
			Optional: optional[a.Type],
		})
	}

	// G1: append ENABLED registry plugins that aren't already built-ins
	// (e.g. semgrep), so they appear in the UI selector / agent list.
	if h.reg != nil {
		for _, p := range h.reg.Enabled() {
			name := p.Name()
			if name == "" || builtinTypes[name] {
				continue
			}
			url := ""
			if h.pluginURL != nil {
				url = h.pluginURL(p)
			}
			display := p.Manifest.Plugin.DisplayName
			if display == "" {
				display = name
			}
			infos = append(infos, model.AgentInfo{
				ID:     name,
				Name:   display,
				Type:   name,
				Status: checkAgentHealth(url),
			})
		}
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
