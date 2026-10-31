package handler

import (
	"context"
	"net/http"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

type contextKey string

const userContextKey contextKey = "user"

// tokenAuthKey marks a request whose principal came from a presented
// credential, not from local mode's implicit local admin (0074 item 1b: a
// masked value is never shown to a request that presented nothing).
const tokenAuthKey contextKey = "token_auth"

type AuthMiddleware struct {
	authSvc          service.AuthService
	streamTokenStore *service.StreamTokenStore
	localUser        *model.User
	apiKeySvc        service.APIKeyService // optional; nil when API keys disabled
}

func NewAuthMiddleware(authSvc service.AuthService) *AuthMiddleware {
	return &AuthMiddleware{authSvc: authSvc}
}

// SetAPIKeyService enables API-key bearer-token auth. Safe to call with nil.
func (m *AuthMiddleware) SetAPIKeyService(svc service.APIKeyService) {
	m.apiKeySvc = svc
}

// SetLocalMode enables local mode by resolving and caching the local admin user.
func (m *AuthMiddleware) SetLocalMode(enabled bool) {
	if !enabled {
		m.localUser = nil
		return
	}
	user, err := m.authSvc.ValidateLocalUser()
	if err != nil {
		m.localUser = nil
		return
	}
	m.localUser = user
}

func (m *AuthMiddleware) Require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := m.extractUser(r)
		ctx := context.WithValue(r.Context(), tokenAuthKey, user != nil)
		if user == nil && m.localUser != nil {
			user = m.localUser
		}
		if user == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		ctx = context.WithValue(ctx, userContextKey, user)
		next(w, r.WithContext(ctx))
	}
}

func (m *AuthMiddleware) Optional(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := m.extractUser(r)
		if user != nil {
			ctx := context.WithValue(r.Context(), userContextKey, user)
			r = r.WithContext(ctx)
		}
		next(w, r)
	}
}

// SetStreamTokenStore sets the stream token store for validating ephemeral SSE tokens.
func (m *AuthMiddleware) SetStreamTokenStore(store *service.StreamTokenStore) {
	m.streamTokenStore = store
}

func (m *AuthMiddleware) extractUser(r *http.Request) *model.User {
	// Check short-lived stream tokens first (only on /api/audits/:id/stream)
	if streamToken := r.URL.Query().Get("stream_token"); streamToken != "" {
		if isAuditStreamPath(r.URL.Path) && m.streamTokenStore != nil {
			auditID := extractAuditIDFromPath(r.URL.Path)
			user, err := m.streamTokenStore.Validate(streamToken, auditID)
			if err == nil {
				return user
			}
		}
		return nil // stream_token was provided but invalid — don't fall through
	}

	token := ""
	// Check Authorization header
	header := r.Header.Get("Authorization")
	if header != "" {
		t := strings.TrimPrefix(header, "Bearer ")
		if t != header {
			token = t
		}
	}
	if token == "" {
		return nil
	}
	// API key path: "vk_" prefix is cheap discriminator.
	// Keep separate from JWT — a failed API-key verify must NOT fall through
	// to JWT, since the two token schemes are not interchangeable.
	if strings.HasPrefix(token, "vk_") {
		if m.apiKeySvc == nil {
			return nil
		}
		key, err := m.apiKeySvc.Verify(token)
		if err != nil || key == nil {
			return nil
		}
		return &model.User{
			ID:   "apikey:" + key.ID,
			Role: "apikey",
		}
	}
	user, err := m.authSvc.ValidateToken(token)
	if err != nil {
		return nil
	}
	return user
}

// isAuditStreamPath returns true only for /api/audits/{id}/stream (not other /stream suffixes)
func isAuditStreamPath(path string) bool {
	trimmed := strings.TrimPrefix(path, "/api/audits/")
	if trimmed == path {
		return false // didn't start with /api/audits/
	}
	// Must be exactly "{id}/stream" — one segment then /stream
	parts := strings.SplitN(trimmed, "/", 2)
	return len(parts) == 2 && parts[0] != "" && parts[1] == "stream"
}

// extractAuditIDFromPath extracts the audit ID from paths like /api/audits/{id}/stream
func extractAuditIDFromPath(path string) string {
	path = strings.TrimPrefix(path, "/api/audits/")
	if idx := strings.Index(path, "/"); idx > 0 {
		return path[:idx]
	}
	return path
}

// isWriteRole reports whether a principal role may perform state-changing
// requests: a human writer (member, admin) or "apikey". "apikey" is included
// deliberately: API-key principals are minted with that synthetic role (see
// Require), keys can only be created by an admin, and they are the documented
// Mode-D / CI write credential (`vulture scan --api-key ...`). Excluding it
// 403s every CI client.
func isWriteRole(role string) bool { return humanWriter(role) || role == "apikey" }

// IsSafeMethod reports whether m is a read-only HTTP method: GET, HEAD or
// OPTIONS, matched exactly as net/http spells them.
func IsSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// requireRoleWhere is the one role gate the Require* wrappers share: it
// answers 403 with msg unless the request's principal has a role that
// allowed admits. Must be applied inside authMW.Require so
// getUserFromContext sees the DB-fresh principal.
func requireRoleWhere(allowed func(string) bool, msg string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if u := getUserFromContext(r); u == nil || !allowed(u.Role) {
			writeError(w, http.StatusForbidden, msg)
			return
		}
		next(w, r)
	}
}

// RequireWrite gates only state-changing methods so combined GET+POST handlers
// (e.g. /api/audits) keep serving reads to viewers (0065 §H1). Safe methods
// pass straight through; writes require a role isWriteRole admits. Must be
// applied inside authMW.Require.
func RequireWrite(next http.HandlerFunc) http.HandlerFunc {
	gated := requireRoleWhere(isWriteRole, "write access requires member, admin, or api-key credentials", next)
	return func(w http.ResponseWriter, r *http.Request) {
		if IsSafeMethod(r.Method) {
			next(w, r)
			return
		}
		gated(w, r)
	}
}

// RequireRole gates an entire handler to a specific role (for /api/admin/*).
// Must be applied inside authMW.Require. 0065 §H7.
func RequireRole(role string, next http.HandlerFunc) http.HandlerFunc {
	return requireRoleWhere(func(r string) bool { return r == role }, "requires "+role+" role", next)
}

// RequireHumanWriter admits only human writers (member or admin), on EVERY
// method, to a route that viewers and API keys have no use for, such as
// folder browse (0102). Must be applied inside authMW.Require.
func RequireHumanWriter(next http.HandlerFunc) http.HandlerFunc {
	return requireRoleWhere(humanWriter, "requires member or admin role", next)
}

func getUserFromContext(r *http.Request) *model.User {
	val := r.Context().Value(userContextKey)
	if val == nil {
		return nil
	}
	user, ok := val.(*model.User)
	if !ok {
		return nil
	}
	return user
}
