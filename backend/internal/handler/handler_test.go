package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/config"
)

func TestHealthHandler(t *testing.T) {
	h := NewHealthHandler()
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "healthy" {
		t.Fatalf("expected healthy, got %s", result["status"])
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusCreated, map[string]string{"key": "value"})

	if w.Code != 201 {
		t.Fatalf("expected 201, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %s", ct)
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "bad request")

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["error"] != "bad request" {
		t.Fatalf("expected 'bad request', got %s", result["error"])
	}
}

func TestAgentHandler_ListReadOnly(t *testing.T) {
	h := NewAgentHandler(map[string]config.AgentConfig{
		"chaos": {Name: "Chaos", Type: "chaos", URL: "http://localhost:8001"},
	})
	h.SetReadOnly(true)

	req := httptest.NewRequest(http.MethodGet, "/api/agents", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var agents []map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&agents)
	if len(agents) != 0 {
		t.Fatalf("expected empty agent list in readonly mode, got %d", len(agents))
	}
}

func TestExtractAuditID(t *testing.T) {
	tests := []struct {
		path   string
		prefix string
		want   string
	}{
		{"/api/audits/abc123", "/api/audits/", "abc123"},
		{"/api/audits/abc123/stream", "/api/audits/", "abc123"},
		{"/api/audits/", "/api/audits/", ""},
	}
	for _, tc := range tests {
		got := extractAuditID(tc.path, tc.prefix)
		if got != tc.want {
			t.Errorf("extractAuditID(%q, %q) = %q, want %q", tc.path, tc.prefix, got, tc.want)
		}
	}
}
