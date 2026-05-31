package handler

import (
	"encoding/json"
	"net/http"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

type AuthHandler struct {
	svc       service.AuthService
	localMode bool
}

func NewAuthHandler(svc service.AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

// SetLocalMode enables or disables local mode (passwordless auth).
func (h *AuthHandler) SetLocalMode(enabled bool) {
	h.localMode = enabled
}

// LocalSession returns a token for the seeded local user without
// credentials. Only available when local mode is enabled. Uses the
// service's password-less IssueLocalAdminToken helper so this handler
// no longer needs to know the (CSPRNG-generated) seed password.
//
// 0036 Phase 3 (H7) — defence-in-depth: even with LocalMode on AND a
// loopback bind enforced (H9 in server.New), reject requests whose
// Host header is not loopback. Catches DNS-rebinding and misconfigured
// reverse-proxy paths.
func (h *AuthHandler) LocalSession(w http.ResponseWriter, r *http.Request) {
	if !h.localMode {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if !isLoopbackHostForLocalSession(r.Host) {
		writeError(w, http.StatusForbidden, "local session requires loopback host")
		return
	}
	resp, err := h.svc.IssueLocalAdminToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "local session unavailable")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// isLoopbackHostForLocalSession is set by the server package at wire
// time. Default permits everything so unit tests of unrelated handlers
// don't need to inject the guard. server.New replaces it with the real
// isLoopbackHost(...) check.
var isLoopbackHostForLocalSession = func(host string) bool { return true }

// SetLoopbackHostCheck wires the server's isLoopbackHost helper into
// this handler. Called from server.New so the production path enforces
// the H7 guard; tests can override via SetLoopbackHostCheck(custom).
func SetLoopbackHostCheck(fn func(host string) bool) {
	if fn == nil {
		fn = func(string) bool { return true }
	}
	isLoopbackHostForLocalSession = fn
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" || req.Password == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "email, password, and name are required")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if len(req.Password) > 72 {
		writeError(w, http.StatusBadRequest, "password must not exceed 72 characters")
		return
	}
	resp, err := h.svc.Register(&req)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resp, err := h.svc.Login(&req)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	writeJSON(w, http.StatusOK, user)
}
