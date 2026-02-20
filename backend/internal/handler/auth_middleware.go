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
	authSvc   service.AuthService
	localUser *model.User
}

func NewAuthMiddleware(authSvc service.AuthService) *AuthMiddleware {
	return &AuthMiddleware{authSvc: authSvc}
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

func (m *AuthMiddleware) extractUser(r *http.Request) *model.User {
	token := ""
	// Check Authorization header first
	header := r.Header.Get("Authorization")
	if header != "" {
		t := strings.TrimPrefix(header, "Bearer ")
		if t != header {
			token = t
		}
	}
	// Fall back to query parameter (needed for EventSource SSE which can't set headers)
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		return nil
	}
	user, err := m.authSvc.ValidateToken(token)
	if err != nil {
		return nil
	}
	return user
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
