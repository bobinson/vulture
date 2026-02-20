package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
)

func TestAgentHandlerList(t *testing.T) {
	agents := map[string]config.AgentConfig{
		"chaos": {Name: "Chaos Engineering", Type: "chaos", URL: "http://agent-chaos:8001"},
		"owasp": {Name: "OWASP Security", Type: "owasp", URL: "http://agent-owasp:8002"},
	}
	h := NewAgentHandler(agents)

	req := httptest.NewRequest("GET", "/api/agents", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var infos []model.AgentInfo
	json.NewDecoder(w.Body).Decode(&infos)
	if len(infos) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(infos))
	}
}

func TestAgentHandlerListEmpty(t *testing.T) {
	h := NewAgentHandler(map[string]config.AgentConfig{})

	req := httptest.NewRequest("GET", "/api/agents", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var infos []model.AgentInfo
	json.NewDecoder(w.Body).Decode(&infos)
	if len(infos) != 0 {
		t.Fatalf("expected 0 agents, got %d", len(infos))
	}
}
