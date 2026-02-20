package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

// LineageHandler handles HTTP requests for finding lineage tracking.
type LineageHandler struct {
	svc service.LineageService
}

// NewLineageHandler creates a new lineage handler.
func NewLineageHandler(svc service.LineageService) *LineageHandler {
	return &LineageHandler{svc: svc}
}

// List handles GET /api/lineage?source_path=...&status=...&limit=20&offset=0
func (h *LineageHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	sourcePath := r.URL.Query().Get("source_path")
	if sourcePath == "" {
		writeError(w, http.StatusBadRequest, "source_path parameter required")
		return
	}
	status := r.URL.Query().Get("status")
	limit := queryInt(r, "limit", 20)
	offset := queryInt(r, "offset", 0)

	lineages, err := h.svc.ListBySourcePath(sourcePath, status, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if lineages == nil {
		lineages = []model.FindingLineage{}
	}
	writeJSON(w, http.StatusOK, lineages)
}

// Get handles GET /api/lineage/:id
func (h *LineageHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := extractLineageID(r.URL.Path)
	if id == "" {
		writeError(w, http.StatusBadRequest, "lineage id required")
		return
	}
	lineage, err := h.svc.GetLineage(id)
	if errors.Is(err, service.ErrNotFound) {
		writeError(w, http.StatusNotFound, "lineage not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Embed events in response
	events, _ := h.svc.GetTimeline(id)
	if events == nil {
		events = []model.LineageEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"lineage": lineage,
		"events":  events,
	})
}

// UpdateStatus handles PATCH /api/lineage/:id
func (h *LineageHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	id := extractLineageID(r.URL.Path)
	if id == "" {
		writeError(w, http.StatusBadRequest, "lineage id required")
		return
	}
	var update model.LineageStatusUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	validStatuses := map[string]bool{
		"open": true, "in_progress": true, "resolved": true,
		"accepted_risk": true, "false_positive": true, "fixed": true,
	}
	if !validStatuses[update.Status] {
		writeError(w, http.StatusBadRequest, "invalid status")
		return
	}
	if err := h.svc.UpdateStatus(id, &update); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			writeError(w, http.StatusNotFound, "lineage not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	updated, err := h.svc.GetLineage(id)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// GetTimeline handles GET /api/lineage/:id/timeline
func (h *LineageHandler) GetTimeline(w http.ResponseWriter, r *http.Request) {
	id := extractTimelineLineageID(r.URL.Path)
	if id == "" {
		writeError(w, http.StatusBadRequest, "lineage id required")
		return
	}
	events, err := h.svc.GetTimeline(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []model.LineageEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

// GetByAudit handles GET /api/audits/:id/lineage
func (h *LineageHandler) GetByAudit(w http.ResponseWriter, r *http.Request) {
	auditID := extractAuditIDForLineage(r.URL.Path)
	if auditID == "" {
		writeError(w, http.StatusBadRequest, "audit id required")
		return
	}
	lineages, err := h.svc.ListByAudit(auditID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if lineages == nil {
		lineages = []model.FindingLineage{}
	}
	writeJSON(w, http.StatusOK, lineages)
}

// extractLineageID extracts ID from /api/lineage/SOME-ID
func extractLineageID(path string) string {
	rest := strings.TrimPrefix(path, "/api/lineage/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// extractTimelineLineageID extracts ID from /api/lineage/SOME-ID/timeline
func extractTimelineLineageID(path string) string {
	rest := strings.TrimPrefix(path, "/api/lineage/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// extractAuditIDForLineage extracts audit ID from /api/audits/SOME-ID/lineage
func extractAuditIDForLineage(path string) string {
	rest := strings.TrimPrefix(path, "/api/audits/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
