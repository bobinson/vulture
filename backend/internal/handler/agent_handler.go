package handler

import (
	"net/http"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
)

type AgentHandler struct {
	agents map[string]config.AgentConfig
}

func NewAgentHandler(agents map[string]config.AgentConfig) *AgentHandler {
	return &AgentHandler{agents: agents}
}

func (h *AgentHandler) List(w http.ResponseWriter, _ *http.Request) {
	infos := make([]model.AgentInfo, 0, len(h.agents))
	for key, a := range h.agents {
		infos = append(infos, model.AgentInfo{
			ID:   key,
			Name: a.Name,
			Type: a.Type,
		})
	}
	writeJSON(w, http.StatusOK, infos)
}
