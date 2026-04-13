package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

// PipelineHandler serves multi-stage pipeline endpoints.
type PipelineHandler struct {
	svc service.PipelineService
}

// NewPipelineHandler creates a handler for pipeline endpoints.
func NewPipelineHandler(svc service.PipelineService) *PipelineHandler {
	return &PipelineHandler{svc: svc}
}

// Create creates a new pipeline with auto-cascading stages.
// POST /api/pipelines
func (h *PipelineHandler) Create(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var req model.PipelineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Stages) == 0 {
		writeError(w, http.StatusBadRequest, "at least one stage required")
		return
	}
	pipeline, err := h.svc.CreatePipeline(&req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, pipeline)
}

// List returns all pipelines.
// GET /api/pipelines
func (h *PipelineHandler) List(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 20)
	offset := queryInt(r, "offset", 0)
	pipelines, err := h.svc.ListPipelines(limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pipelines == nil {
		pipelines = []model.Pipeline{}
	}
	writeJSON(w, http.StatusOK, pipelines)
}

// Get returns a single pipeline by ID.
// GET /api/pipelines/{id}
func (h *PipelineHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := extractPipelineID(r.URL.Path)
	if id == "" {
		writeError(w, http.StatusBadRequest, "pipeline id required")
		return
	}
	pipeline, err := h.svc.GetPipeline(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pipeline == nil {
		writeError(w, http.StatusNotFound, "pipeline not found")
		return
	}
	writeJSON(w, http.StatusOK, pipeline)
}

func extractPipelineID(path string) string {
	prefix := "/api/pipelines/"
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	return parts[0]
}
