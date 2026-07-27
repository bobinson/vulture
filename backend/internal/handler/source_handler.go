package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

type SourceHandler struct {
	svc service.SourceService
}

func NewSourceHandler(svc service.SourceService) *SourceHandler {
	return &SourceHandler{svc: svc}
}

func (h *SourceHandler) Create(w http.ResponseWriter, r *http.Request) {
	// Write-only endpoint: reject read verbs. The route is wrapped in
	// method-gated RequireWrite, which passes GET/HEAD/OPTIONS through WITHOUT a
	// role check; since this handler is mounted for all methods on /api/sources,
	// a non-POST verb must be refused here or a viewer/apikey principal could
	// enter the ingest (git-clone) path via a read verb (0065 security-review).
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	var req model.SourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Type == "" {
		writeError(w, http.StatusBadRequest, "type is required")
		return
	}
	src, err := h.svc.Ingest(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, src)
}

func (h *SourceHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/sources/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "source id required")
		return
	}
	src, err := h.svc.Get(id)
	if errors.Is(err, service.ErrNotFound) {
		writeError(w, http.StatusNotFound, "source not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, src)
}
