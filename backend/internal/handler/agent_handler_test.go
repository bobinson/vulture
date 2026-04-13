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
	// Start mock agent servers that respond to /health
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()
	unhealthySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unhealthySrv.Close()

	agents := map[string]config.AgentConfig{
		"chaos": {Name: "Chaos Engineering", Type: "chaos", URL: healthy.URL},
		"owasp": {Name: "OWASP Security", Type: "owasp", URL: unhealthySrv.URL},
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

	// Verify status fields are populated
	statusMap := make(map[string]string)
	for _, info := range infos {
		statusMap[info.Type] = info.Status
	}
	if statusMap["chaos"] != "healthy" {
		t.Errorf("expected chaos=healthy, got %s", statusMap["chaos"])
	}
	if statusMap["owasp"] != "unhealthy" {
		t.Errorf("expected owasp=unhealthy, got %s", statusMap["owasp"])
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

func TestCheckAgentHealth_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	status := checkAgentHealth(srv.URL)
	if status != "healthy" {
		t.Errorf("expected healthy, got %s", status)
	}
}

func TestCheckAgentHealth_Unhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	status := checkAgentHealth(srv.URL)
	if status != "unhealthy" {
		t.Errorf("expected unhealthy, got %s", status)
	}
}

func TestCheckAgentHealth_Unreachable(t *testing.T) {
	status := checkAgentHealth("http://localhost:1")
	if status != "unhealthy" {
		t.Errorf("expected unhealthy for unreachable, got %s", status)
	}
}

func TestCheckAgentHealth_EmptyURL(t *testing.T) {
	status := checkAgentHealth("")
	if status != "unknown" {
		t.Errorf("expected unknown for empty URL, got %s", status)
	}
}
