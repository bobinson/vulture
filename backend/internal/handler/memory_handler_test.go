package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

func TestMemoryHandlerSearchWithQuery(t *testing.T) {
	svc := &mockMemoryService{
		searchFn: func(req *model.MemorySearchRequest) ([]model.AuditMemory, error) {
			if req.Query != "sql injection" {
				t.Errorf("expected query 'sql injection', got %q", req.Query)
			}
			return []model.AuditMemory{{ID: "m-1", Title: "SQL Injection"}}, nil
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/search?q=sql+injection", nil)
	w := httptest.NewRecorder()
	h.Search(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var memories []model.AuditMemory
	json.NewDecoder(w.Body).Decode(&memories)
	if len(memories) != 1 {
		t.Fatalf("expected 1 memory, got %d", len(memories))
	}
}

func TestMemoryHandlerSearchEmptyQuery(t *testing.T) {
	svc := &mockMemoryService{
		listRecentFn: func(limit int) ([]model.AuditMemory, error) {
			return []model.AuditMemory{{ID: "m-recent"}}, nil
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/search", nil)
	w := httptest.NewRecorder()
	h.Search(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMemoryHandlerSearchEmptyQueryNilResult(t *testing.T) {
	svc := &mockMemoryService{
		listRecentFn: func(limit int) ([]model.AuditMemory, error) {
			return nil, nil
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/search", nil)
	w := httptest.NewRecorder()
	h.Search(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var memories []model.AuditMemory
	json.NewDecoder(w.Body).Decode(&memories)
	if len(memories) != 0 {
		t.Fatalf("nil should become empty array, got %d", len(memories))
	}
}

func TestMemoryHandlerSearchEmptyQueryError(t *testing.T) {
	svc := &mockMemoryService{
		listRecentFn: func(limit int) ([]model.AuditMemory, error) {
			return nil, errors.New("db error")
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/search", nil)
	w := httptest.NewRecorder()
	h.Search(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestMemoryHandlerSearchError(t *testing.T) {
	svc := &mockMemoryService{
		searchFn: func(req *model.MemorySearchRequest) ([]model.AuditMemory, error) {
			return nil, errors.New("search failed")
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/search?q=test", nil)
	w := httptest.NewRecorder()
	h.Search(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestMemoryHandlerSearchNilResult(t *testing.T) {
	svc := &mockMemoryService{
		searchFn: func(req *model.MemorySearchRequest) ([]model.AuditMemory, error) {
			return nil, nil
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/search?q=test", nil)
	w := httptest.NewRecorder()
	h.Search(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMemoryHandlerGet(t *testing.T) {
	svc := &mockMemoryService{
		getWithEdgesFn: func(id string) (*model.MemoryWithEdges, error) {
			return &model.MemoryWithEdges{AuditMemory: model.AuditMemory{ID: id, Title: "Test"}}, nil
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/m-1", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMemoryHandlerGetMissingID(t *testing.T) {
	h := NewMemoryHandler(&mockMemoryService{})

	req := httptest.NewRequest("GET", "/api/memories/", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestMemoryHandlerGetNotFound(t *testing.T) {
	svc := &mockMemoryService{
		getWithEdgesFn: func(id string) (*model.MemoryWithEdges, error) {
			return nil, service.ErrNotFound
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/missing", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestMemoryHandlerGetInternalError(t *testing.T) {
	svc := &mockMemoryService{
		getWithEdgesFn: func(id string) (*model.MemoryWithEdges, error) {
			return nil, errors.New("db error")
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/err", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestMemoryHandlerGetEdges(t *testing.T) {
	svc := &mockMemoryService{
		getEdgesFn: func(memoryID string) ([]model.MemoryEdge, error) {
			return []model.MemoryEdge{{ID: "e-1", SourceID: memoryID}}, nil
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/m-1/edges", nil)
	w := httptest.NewRecorder()
	h.GetEdges(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMemoryHandlerGetEdgesMissingID(t *testing.T) {
	h := NewMemoryHandler(&mockMemoryService{})

	req := httptest.NewRequest("GET", "/api/memories//edges", nil)
	w := httptest.NewRecorder()
	h.GetEdges(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestMemoryHandlerGetEdgesNilResult(t *testing.T) {
	svc := &mockMemoryService{
		getEdgesFn: func(memoryID string) ([]model.MemoryEdge, error) {
			return nil, nil
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/m-1/edges", nil)
	w := httptest.NewRecorder()
	h.GetEdges(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMemoryHandlerGetEdgesError(t *testing.T) {
	svc := &mockMemoryService{
		getEdgesFn: func(memoryID string) ([]model.MemoryEdge, error) {
			return nil, errors.New("db error")
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/m-1/edges", nil)
	w := httptest.NewRecorder()
	h.GetEdges(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestMemoryHandlerUpdateRemediation(t *testing.T) {
	svc := &mockMemoryService{
		updateRemFn: func(id, status, notes string) error {
			if status != "resolved" {
				t.Errorf("expected resolved, got %s", status)
			}
			return nil
		},
	}
	h := NewMemoryHandler(svc)

	body := `{"status":"resolved","notes":"fixed in PR #42"}`
	req := httptest.NewRequest("PATCH", "/api/memories/m-1", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.UpdateRemediation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMemoryHandlerUpdateRemediationMissingID(t *testing.T) {
	h := NewMemoryHandler(&mockMemoryService{})

	body := `{"status":"resolved"}`
	req := httptest.NewRequest("PATCH", "/api/memories/", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.UpdateRemediation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestMemoryHandlerUpdateRemediationBadJSON(t *testing.T) {
	h := NewMemoryHandler(&mockMemoryService{})

	req := httptest.NewRequest("PATCH", "/api/memories/m-1", bytes.NewBufferString("{bad"))
	w := httptest.NewRecorder()
	h.UpdateRemediation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestMemoryHandlerUpdateRemediationInvalidStatus(t *testing.T) {
	h := NewMemoryHandler(&mockMemoryService{})

	body := `{"status":"invalid_status"}`
	req := httptest.NewRequest("PATCH", "/api/memories/m-1", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.UpdateRemediation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestMemoryHandlerUpdateRemediationError(t *testing.T) {
	svc := &mockMemoryService{
		updateRemFn: func(id, status, notes string) error {
			return errors.New("db error")
		},
	}
	h := NewMemoryHandler(svc)

	body := `{"status":"open"}`
	req := httptest.NewRequest("PATCH", "/api/memories/m-1", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.UpdateRemediation(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestMemoryHandlerListByAudit(t *testing.T) {
	svc := &mockMemoryService{
		listByAuditFn: func(auditID string) ([]model.AuditMemory, error) {
			return []model.AuditMemory{{ID: "m-1"}}, nil
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories?audit_id=a-1", nil)
	w := httptest.NewRecorder()
	h.ListByAudit(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMemoryHandlerListByAuditMissingParam(t *testing.T) {
	h := NewMemoryHandler(&mockMemoryService{})

	req := httptest.NewRequest("GET", "/api/memories", nil)
	w := httptest.NewRecorder()
	h.ListByAudit(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestMemoryHandlerListByAuditError(t *testing.T) {
	svc := &mockMemoryService{
		listByAuditFn: func(auditID string) ([]model.AuditMemory, error) {
			return nil, errors.New("db error")
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories?audit_id=a-1", nil)
	w := httptest.NewRecorder()
	h.ListByAudit(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestMemoryHandlerListByAuditNilResult(t *testing.T) {
	svc := &mockMemoryService{
		listByAuditFn: func(auditID string) ([]model.AuditMemory, error) {
			return nil, nil
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories?audit_id=a-1", nil)
	w := httptest.NewRecorder()
	h.ListByAudit(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMemoryHandlerListByCodebasePath(t *testing.T) {
	svc := &mockMemoryService{
		listByCodebasePathFn: func(path, agentType string, limit int) ([]model.AuditMemory, error) {
			if path != "/src/app" {
				t.Errorf("expected /src/app, got %s", path)
			}
			return []model.AuditMemory{{ID: "m-1"}}, nil
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/by-path?path=/src/app&agent_type=owasp&limit=10", nil)
	w := httptest.NewRecorder()
	h.ListByCodebasePath(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMemoryHandlerListByCodebasePathMissing(t *testing.T) {
	h := NewMemoryHandler(&mockMemoryService{})

	req := httptest.NewRequest("GET", "/api/memories/by-path", nil)
	w := httptest.NewRecorder()
	h.ListByCodebasePath(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestMemoryHandlerListByCodebasePathError(t *testing.T) {
	svc := &mockMemoryService{
		listByCodebasePathFn: func(path, agentType string, limit int) ([]model.AuditMemory, error) {
			return nil, errors.New("db error")
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/by-path?path=/code", nil)
	w := httptest.NewRecorder()
	h.ListByCodebasePath(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestMemoryHandlerListByCodebasePathNilResult(t *testing.T) {
	svc := &mockMemoryService{
		listByCodebasePathFn: func(path, agentType string, limit int) ([]model.AuditMemory, error) {
			return nil, nil
		},
	}
	h := NewMemoryHandler(svc)

	req := httptest.NewRequest("GET", "/api/memories/by-path?path=/code", nil)
	w := httptest.NewRecorder()
	h.ListByCodebasePath(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestExtractMemoryID(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/memories/abc123", "abc123"},
		{"/api/memories/abc123/edges", "abc123"},
		{"/api/memories/", ""},
	}
	for _, tc := range tests {
		got := extractMemoryID(tc.path)
		if got != tc.want {
			t.Errorf("extractMemoryID(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestExtractEdgeMemoryID(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/memories/abc123/edges", "abc123"},
		{"/api/memories/", ""},
	}
	for _, tc := range tests {
		got := extractEdgeMemoryID(tc.path)
		if got != tc.want {
			t.Errorf("extractEdgeMemoryID(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestUpdateRemediationAllValidStatuses(t *testing.T) {
	validStatuses := []string{"open", "in_progress", "resolved", "accepted_risk", "false_positive"}

	for _, status := range validStatuses {
		svc := &mockMemoryService{}
		h := NewMemoryHandler(svc)

		body := `{"status":"` + status + `"}`
		req := httptest.NewRequest("PATCH", "/api/memories/m-1", bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		h.UpdateRemediation(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status %q: expected 200, got %d", status, w.Code)
		}
	}
}
