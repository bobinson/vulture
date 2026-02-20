package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

type MemoryHandler struct {
	svc service.MemoryService
}

func NewMemoryHandler(svc service.MemoryService) *MemoryHandler {
	return &MemoryHandler{svc: svc}
}

func (h *MemoryHandler) Search(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	limit := queryInt(r, "limit", 20)

	// When query is empty, return recent memories instead of erroring
	if query == "" {
		memories, err := h.svc.ListRecent(limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if memories == nil {
			memories = []model.AuditMemory{}
		}
		writeJSON(w, http.StatusOK, memories)
		return
	}

	req := &model.MemorySearchRequest{
		Query:     query,
		AuditID:   r.URL.Query().Get("audit_id"),
		AgentType: r.URL.Query().Get("agent_type"),
		Severity:  r.URL.Query().Get("severity"),
		Limit:     limit,
	}
	memories, err := h.svc.Search(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if memories == nil {
		memories = []model.AuditMemory{}
	}
	writeJSON(w, http.StatusOK, memories)
}

func (h *MemoryHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := extractMemoryID(r.URL.Path)
	if id == "" {
		writeError(w, http.StatusBadRequest, "memory id required")
		return
	}
	// Return memory with edges for graph display
	mem, err := h.svc.GetWithEdges(id)
	if errors.Is(err, service.ErrNotFound) {
		writeError(w, http.StatusNotFound, "memory not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, mem)
}

func (h *MemoryHandler) GetEdges(w http.ResponseWriter, r *http.Request) {
	id := extractEdgeMemoryID(r.URL.Path)
	if id == "" {
		writeError(w, http.StatusBadRequest, "memory id required")
		return
	}
	edges, err := h.svc.GetEdges(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if edges == nil {
		edges = []model.MemoryEdge{}
	}
	writeJSON(w, http.StatusOK, edges)
}

func (h *MemoryHandler) UpdateRemediation(w http.ResponseWriter, r *http.Request) {
	id := extractMemoryID(r.URL.Path)
	if id == "" {
		writeError(w, http.StatusBadRequest, "memory id required")
		return
	}
	var req struct {
		Status string `json:"status"`
		Notes  string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	validStatuses := map[string]bool{
		"open": true, "in_progress": true, "resolved": true,
		"accepted_risk": true, "false_positive": true,
	}
	if !validStatuses[req.Status] {
		writeError(w, http.StatusBadRequest, "invalid remediation status")
		return
	}
	if err := h.svc.UpdateRemediation(id, req.Status, req.Notes); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *MemoryHandler) ListByAudit(w http.ResponseWriter, r *http.Request) {
	auditID := r.URL.Query().Get("audit_id")
	if auditID == "" {
		writeError(w, http.StatusBadRequest, "audit_id parameter required")
		return
	}
	memories, err := h.svc.ListByAudit(auditID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if memories == nil {
		memories = []model.AuditMemory{}
	}
	writeJSON(w, http.StatusOK, memories)
}

func (h *MemoryHandler) ListByCodebasePath(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeError(w, http.StatusBadRequest, "path parameter required")
		return
	}
	agentType := r.URL.Query().Get("agent_type")
	limit := queryInt(r, "limit", 50)
	memories, err := h.svc.ListByCodebasePath(path, agentType, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if memories == nil {
		memories = []model.AuditMemory{}
	}
	writeJSON(w, http.StatusOK, memories)
}

func extractMemoryID(path string) string {
	rest := strings.TrimPrefix(path, "/api/memories/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// extractEdgeMemoryID extracts the memory ID from /api/memories/:id/edges
func extractEdgeMemoryID(path string) string {
	rest := strings.TrimPrefix(path, "/api/memories/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
