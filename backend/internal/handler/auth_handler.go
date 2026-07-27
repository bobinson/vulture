package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

// LoginThrottle gates repeated login failures per (email, IP). It is
// satisfied by the server package's throttle and injected at wire time
// (0065 F6). nil in unit tests that don't exercise throttling.
type LoginThrottle interface {
	// Delay returns how long to stall before this (email,ip) may attempt;
	// a negative value means reject immediately (hard ceiling, §R5).
	Delay(email, ip string) time.Duration
	Fail(email, ip string)
	Reset(email, ip string)
}

type AuthHandler struct {
	svc       service.AuthService
	localMode bool
	throttle  LoginThrottle
	clientIP  func(*http.Request) string
}

func NewAuthHandler(svc service.AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

// SetLoginThrottle wires the login throttle and the client-IP extractor
// (both from the server package) into the handler. Called from server.New;
// when unset, Login proceeds without throttling. 0065 F6.
func (h *AuthHandler) SetLoginThrottle(t LoginThrottle, clientIP func(*http.Request) string) {
	h.throttle = t
	h.clientIP = clientIP
}

// loginClientIP resolves the client IP for throttle keying, falling back to
// RemoteAddr when no extractor is wired (unit tests).
func (h *AuthHandler) loginClientIP(r *http.Request) string {
	if h.clientIP != nil {
		return h.clientIP(r)
	}
	return r.RemoteAddr
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

// decodeRegisterRequest decodes and validates a registration payload,
// writing the appropriate 400 and returning ok=false on failure. Shared
// by Register (self-service) and AdminCreateUser (admin provisioning) so
// the validation contract is single-sourced (0065 §H7).
func decodeRegisterRequest(w http.ResponseWriter, r *http.Request) (*model.RegisterRequest, bool) {
	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return nil, false
	}
	if req.Email == "" || req.Password == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "email, password, and name are required")
		return nil, false
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return nil, false
	}
	if len(req.Password) > 72 {
		writeError(w, http.StatusBadRequest, "password must not exceed 72 characters")
		return nil, false
	}
	return &req, true
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeRegisterRequest(w, r)
	if !ok {
		return
	}
	resp, err := h.svc.Register(req)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

// AdminCreateUser provisions a new user on behalf of an administrator. It
// reuses the service's Register hashing/creation but, unlike self-service
// registration, it does NOT self-authenticate the created user — only the
// created principal is returned, never a session token for them (0065 §H7).
// Role-gating to "admin" is enforced by the caller via RequireRole.
func (h *AuthHandler) AdminCreateUser(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeRegisterRequest(w, r)
	if !ok {
		return
	}
	resp, err := h.svc.Register(req)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, resp.User)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	email, ip := req.Email, h.loginClientIP(r)
	if h.throttle != nil {
		switch d := h.throttle.Delay(email, ip); {
		case d < 0: // §R5 hard ceiling: reject without parking a goroutine
			writeError(w, http.StatusTooManyRequests, "too many attempts, try again later")
			return
		case d > 0:
			time.Sleep(d) // escalating, capped at maxSleep
		}
	}
	resp, err := h.svc.Login(&req)
	if err != nil {
		if h.throttle != nil {
			h.throttle.Fail(email, ip)
		}
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if h.throttle != nil {
		h.throttle.Reset(email, ip)
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
