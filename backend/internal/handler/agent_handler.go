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

	// Flag Optional built-in agents (the UI badges opt-in agents in the selector).
	optional := make(map[string]bool, len(agentregistry.AllAgents))
	for _, e := range agentregistry.AllAgents {
		if e.Optional {
			optional[e.Type] = true
		}
	}

	// Collect every probe target — built-in agents PLUS enabled registry plugins
	// (G1) that aren't already built-ins (the registry also carries in-tree
	// agents as virtual plugins, so dedupe by type). They are health-checked in
	// ONE concurrent wave so /api/agents latency stays ~one 2s timeout, not N.
	type target struct {
		url  string
		info model.AgentInfo
	}
	targets := make([]target, 0, len(h.agents)+4)
	builtinTypes := make(map[string]bool, len(h.agents))
	for key, a := range h.agents {
		builtinTypes[a.Type] = true
		targets = append(targets, target{
			url:  a.URL,
			info: model.AgentInfo{ID: key, Name: a.Name, Type: a.Type, Optional: optional[a.Type]},
		})
	}
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
			targets = append(targets, target{
				url:  url,
				info: model.AgentInfo{ID: name, Name: display, Type: name},
			})
		}
	}

	// Concurrent health probe — one goroutine per target (2s timeout each).
	var wg sync.WaitGroup
	statuses := make([]string, len(targets))
	for i := range targets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			statuses[i] = checkAgentHealth(targets[i].url)
		}(i)
	}
	wg.Wait()

	infos := make([]model.AgentInfo, len(targets))
	for i := range targets {
		infos[i] = targets[i].info
		infos[i].Status = statuses[i]
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
