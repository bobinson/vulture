package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

type mockLineageService struct {
	getLineageFn       func(string) (*model.FindingLineage, error)
	listBySourcePathFn func(string, string, int, int) ([]model.FindingLineage, error)
	listByAuditFn      func(string) ([]model.FindingLineage, error)
	updateStatusFn     func(string, *model.LineageStatusUpdate) error
	getTimelineFn      func(string) ([]model.LineageEvent, error)
}

func (m *mockLineageService) ProcessAuditFindings(a *model.Audit, s *model.Source, f []model.Finding) error {
	return nil
}
func (m *mockLineageService) GetLineage(id string) (*model.FindingLineage, error) {
	if m.getLineageFn != nil {
		return m.getLineageFn(id)
	}
	return nil, service.ErrNotFound
}
func (m *mockLineageService) GetLineageForFinding(fp, sp, at string) (*model.FindingLineage, error) {
	return nil, service.ErrNotFound
}
func (m *mockLineageService) ListBySourcePath(sp, status string, limit, offset int) ([]model.FindingLineage, error) {
	if m.listBySourcePathFn != nil {
		return m.listBySourcePathFn(sp, status, limit, offset)
	}
	return nil, nil
}
func (m *mockLineageService) ListByAudit(auditID string) ([]model.FindingLineage, error) {
	if m.listByAuditFn != nil {
		return m.listByAuditFn(auditID)
	}
	return nil, nil
}
func (m *mockLineageService) UpdateStatus(id string, u *model.LineageStatusUpdate) error {
	if m.updateStatusFn != nil {
		return m.updateStatusFn(id, u)
	}
	return nil
}
func (m *mockLineageService) GetTimeline(id string) ([]model.LineageEvent, error) {
	if m.getTimelineFn != nil {
		return m.getTimelineFn(id)
	}
	return nil, nil
}

func TestLineageHandler_List(t *testing.T) {
	now := time.Now()
	svc := &mockLineageService{
		listBySourcePathFn: func(sp, status string, limit, offset int) ([]model.FindingLineage, error) {
			return []model.FindingLineage{
				{ID: "l-1", Fingerprint: "fp-1", SourcePath: sp, CurrentStatus: model.LineageStatusOpen, CreatedAt: now, UpdatedAt: now, FirstFoundAt: now},
			}, nil
		},
	}
	h := NewLineageHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/lineage?source_path=/test", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result []model.FindingLineage
	json.NewDecoder(w.Body).Decode(&result)
	if len(result) != 1 {
		t.Errorf("expected 1 lineage, got %d", len(result))
	}
}

func TestLineageHandler_List_MissingSourcePath(t *testing.T) {
	h := NewLineageHandler(&mockLineageService{})
	req := httptest.NewRequest(http.MethodGet, "/api/lineage", nil)
	w := httptest.NewRecorder()
	h.List(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestLineageHandler_Get_NotFound(t *testing.T) {
	h := NewLineageHandler(&mockLineageService{})
	req := httptest.NewRequest(http.MethodGet, "/api/lineage/nonexistent", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestLineageHandler_UpdateStatus(t *testing.T) {
	now := time.Now()
	svc := &mockLineageService{
		updateStatusFn: func(id string, u *model.LineageStatusUpdate) error { return nil },
		getLineageFn: func(id string) (*model.FindingLineage, error) {
			return &model.FindingLineage{ID: id, CurrentStatus: model.LineageStatusInProgress, CreatedAt: now, UpdatedAt: now, FirstFoundAt: now}, nil
		},
	}
	h := NewLineageHandler(svc)

	body, _ := json.Marshal(model.LineageStatusUpdate{Status: "in_progress", Notes: "working"})
	req := httptest.NewRequest(http.MethodPatch, "/api/lineage/l-1", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.UpdateStatus(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLineageHandler_UpdateStatus_InvalidStatus(t *testing.T) {
	h := NewLineageHandler(&mockLineageService{})
	body, _ := json.Marshal(model.LineageStatusUpdate{Status: "invalid_status"})
	req := httptest.NewRequest(http.MethodPatch, "/api/lineage/l-1", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.UpdateStatus(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestLineageHandler_UpdateStatus_NotFound(t *testing.T) {
	svc := &mockLineageService{
		updateStatusFn: func(id string, u *model.LineageStatusUpdate) error { return service.ErrNotFound },
	}
	h := NewLineageHandler(svc)

	body, _ := json.Marshal(model.LineageStatusUpdate{Status: "open"})
	req := httptest.NewRequest(http.MethodPatch, "/api/lineage/l-1", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.UpdateStatus(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestLineageHandler_GetTimeline(t *testing.T) {
	svc := &mockLineageService{
		getTimelineFn: func(id string) ([]model.LineageEvent, error) {
			return []model.LineageEvent{
				{ID: "e-1", LineageID: id, EventType: model.LineageEventDetected, CreatedAt: time.Now()},
			}, nil
		},
	}
	h := NewLineageHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/lineage/l-1/timeline", nil)
	w := httptest.NewRecorder()
	h.GetTimeline(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestLineageHandler_GetByAudit(t *testing.T) {
	now := time.Now()
	svc := &mockLineageService{
		listByAuditFn: func(auditID string) ([]model.FindingLineage, error) {
			return []model.FindingLineage{
				{ID: "l-1", Fingerprint: "fp-1", CurrentStatus: model.LineageStatusOpen, CreatedAt: now, UpdatedAt: now, FirstFoundAt: now},
			}, nil
		},
	}
	h := NewLineageHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/audits/audit-1/lineage", nil)
	w := httptest.NewRecorder()
	h.GetByAudit(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestLineageHandler_GetByAudit_Error(t *testing.T) {
	svc := &mockLineageService{
		listByAuditFn: func(auditID string) ([]model.FindingLineage, error) {
			return nil, errors.New("db error")
		},
	}
	h := NewLineageHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/audits/audit-1/lineage", nil)
	w := httptest.NewRecorder()
	h.GetByAudit(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}
