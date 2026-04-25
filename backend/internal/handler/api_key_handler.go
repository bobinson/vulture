package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/vulture/backend/internal/service"
)

// APIKeyHandler serves /api/api-keys CRUD endpoints.
// All operations require Role == "admin" (checked per-handler since
// no RequireAdmin middleware exists in this codebase).
type APIKeyHandler struct {
	svc service.APIKeyService
}

func NewAPIKeyHandler(svc service.APIKeyService) *APIKeyHandler {
	return &APIKeyHandler{svc: svc}
}

// CreateOrList dispatches GET/POST on /api/api-keys.
func (h *APIKeyHandler) CreateOrList(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.List(w, r)
	case http.MethodPost:
		h.Create(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// Create mints a new API key. Returns the plaintext EXACTLY ONCE.
func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := requireAdmin(w, r)
	if user == nil {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	plaintext, stored, err := h.svc.Create(strings.TrimSpace(req.Name), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create api key")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":         stored.ID,
		"prefix":     stored.Prefix,
		"name":       stored.Name,
		"scopes":     stored.Scopes,
		"created_at": stored.CreatedAt,
		"key":        plaintext, // shown ONCE — caller must save
	})
}

// List returns non-revoked keys created by the caller. Never returns Hash.
func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	user := requireAdmin(w, r)
	if user == nil {
		return
	}
	keys, err := h.svc.List(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list api keys")
		return
	}
	out := make([]map[string]interface{}, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]interface{}{
			"id":           k.ID,
			"prefix":       k.Prefix,
			"name":         k.Name,
			"scopes":       k.Scopes,
			"created_at":   k.CreatedAt,
			"last_used_at": k.LastUsedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// Revoke handles DELETE /api/api-keys/{id}.
func (h *APIKeyHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	user := requireAdmin(w, r)
	if user == nil {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/api-keys/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	if err := h.svc.Revoke(id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke api key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// requireAdmin returns the user only if authenticated and admin. Writes
// 401/403 and returns nil otherwise.
func requireAdmin(w http.ResponseWriter, r *http.Request) *userRef {
	u := getUserFromContext(r)
	if u == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil
	}
	if u.Role != "admin" {
		writeError(w, http.StatusForbidden, "admin access required")
		return nil
	}
	return &userRef{ID: u.ID, Role: u.Role}
}

// userRef is a shallow copy used inside handlers — avoids exporting model dep here.
type userRef struct {
	ID   string
	Role string
}
