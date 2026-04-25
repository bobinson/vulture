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
		if user == nil && m.localUser != nil {
			user = m.localUser
		}
		if user == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey, user)
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
