package handler

import (
	"net/http"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

// ProveHandler serves prove verification results.
type ProveHandler struct {
	svc service.ProveService
}

// NewProveHandler creates a handler for prove result endpoints.
func NewProveHandler(svc service.ProveService) *ProveHandler {
	return &ProveHandler{svc: svc}
}

// GetResults returns all prove results for an audit.
// GET /api/audits/{id}/prove-results
func (h *ProveHandler) GetResults(w http.ResponseWriter, r *http.Request) {
	id := extractProveAuditID(r.URL.Path, "/prove-results")
	if id == "" {
		writeError(w, http.StatusBadRequest, "audit id required")
		return
	}
	results, err := h.svc.GetResults(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if results == nil {
		results = []model.ProveResult{}
	}
	writeJSON(w, http.StatusOK, results)
}

// GetSummary returns aggregated prove stats for an audit.
// GET /api/audits/{id}/prove-summary
func (h *ProveHandler) GetSummary(w http.ResponseWriter, r *http.Request) {
	id := extractProveAuditID(r.URL.Path, "/prove-summary")
	if id == "" {
		writeError(w, http.StatusBadRequest, "audit id required")
		return
	}
	summary, err := h.svc.GetSummary(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// GetResultsByFingerprint returns prove results across all audits for a given fingerprint.
// GET /api/prove-results?fingerprint=...
func (h *ProveHandler) GetResultsByFingerprint(w http.ResponseWriter, r *http.Request) {
	fp := r.URL.Query().Get("fingerprint")
	if fp == "" {
		writeError(w, http.StatusBadRequest, "fingerprint query parameter required")
		return
	}
	results, err := h.svc.GetResultsByFingerprint(fp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if results == nil {
		results = []model.ProveResult{}
	}
	writeJSON(w, http.StatusOK, results)
}

// extractProveAuditID extracts the audit ID from paths like /api/audits/{id}/prove-results
func extractProveAuditID(path, suffix string) string {
	path = strings.TrimSuffix(path, suffix)
	prefix := "/api/audits/"
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
