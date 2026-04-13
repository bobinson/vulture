package handler

import (
	"net/http"
	"strings"

	"github.com/vulture/backend/internal/service"
)

// DiscoverHandler serves discover result endpoints.
type DiscoverHandler struct {
	svc service.DiscoverService
}

// NewDiscoverHandler creates a handler for discover result endpoints.
func NewDiscoverHandler(svc service.DiscoverService) *DiscoverHandler {
	return &DiscoverHandler{svc: svc}
}

// GetByAudit returns the discover result for an audit.
// GET /api/audits/{id}/discover-result
func (h *DiscoverHandler) GetByAudit(w http.ResponseWriter, r *http.Request) {
	id := extractDiscoverAuditID(r.URL.Path)
	if id == "" {
		writeError(w, http.StatusBadRequest, "audit id required")
		return
	}
	result, err := h.svc.GetResultByAuditID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if result == nil {
		writeError(w, http.StatusNotFound, "discover result not found")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// GetByTarget returns the latest discover result for a target URL.
// GET /api/discover-results?target_url=...
func (h *DiscoverHandler) GetByTarget(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("target_url")
	if targetURL == "" {
		writeError(w, http.StatusBadRequest, "target_url query parameter required")
		return
	}
	result, err := h.svc.GetResultByTarget(targetURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if result == nil {
		writeError(w, http.StatusNotFound, "no discover result for target")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func extractDiscoverAuditID(path string) string {
	path = strings.TrimSuffix(path, "/discover-result")
	prefix := "/api/audits/"
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
