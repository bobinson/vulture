package handler

import (
	"net/http"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

// canonicalAuditID normalises a 32-char hex audit ID into the
// hyphenated 8-4-4-4-12 UUID form so it matches the value stored in
// `prove_results.audit_id` (which is TEXT, not UUID — so the
// hyphen-less form returns zero rows even when 15 rows exist).
//
// The `audits.id` column is UUID and Postgres canonicalises both
// forms transparently — that's why `/api/audits/{id}` accepts both.
// `prove_results.audit_id` doesn't get that for free.
//
// Bug fix 2026-05-29: a fresh `vulture prove` run persisted 15
// prove_results with hyphenated audit_id, but the CLI and UI queried
// the prove-results endpoint with the hyphen-less form, got `[]`,
// and reported "Findings: 0".
func canonicalAuditID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) == 32 && !strings.ContainsRune(id, '-') {
		// Re-insert hyphens at the UUID positions.
		return id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:]
	}
	return id
}

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
	id := canonicalAuditID(extractProveAuditID(r.URL.Path, "/prove-results"))
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
	id := canonicalAuditID(extractProveAuditID(r.URL.Path, "/prove-summary"))
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
