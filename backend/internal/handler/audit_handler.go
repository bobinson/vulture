package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

type AuditHandler struct {
	svc service.AuditService
}

func NewAuditHandler(svc service.AuditService) *AuditHandler {
	return &AuditHandler{svc: svc}
}

func (h *AuditHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req model.AuditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	audit, err := h.svc.Create(&req)
	if errors.Is(err, service.ErrNotFound) {
		writeError(w, http.StatusNotFound, "source not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, audit)
}

func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 20)
	offset := queryInt(r, "offset", 0)
	audits, err := h.svc.List(limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if audits == nil {
		audits = []model.Audit{}
	}
	writeJSON(w, http.StatusOK, audits)
}

func (h *AuditHandler) Stats(w http.ResponseWriter, _ *http.Request) {
	stats, err := h.svc.Stats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (h *AuditHandler) CachedAudit(w http.ResponseWriter, r *http.Request) {
	sourceID := r.URL.Query().Get("source_id")
	typesParam := r.URL.Query().Get("types")
	if sourceID == "" || typesParam == "" {
		writeError(w, http.StatusBadRequest, "source_id and types are required")
		return
	}
	types := strings.Split(typesParam, ",")
	audit, err := h.svc.GetCachedAudit(sourceID, types)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if audit == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"cached": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"cached": true,
		"audit":  audit,
	})
}

func (h *AuditHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := extractAuditID(r.URL.Path, "/api/audits/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "audit id required")
		return
	}
	audit, err := h.svc.Get(id)
	if errors.Is(err, service.ErrNotFound) {
		writeError(w, http.StatusNotFound, "audit not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, audit)
}

func extractAuditID(path, prefix string) string {
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func queryInt(r *http.Request, key string, fallback int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
