package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// TestRequireWrite_RolePolicy pins which principals may perform writes.
//
// Regression guard: API-key principals are minted with Role "apikey"
// (auth_middleware.go), and API keys are the documented Mode-D / CI write
// credential (`vulture scan --api-key ...`). 0065 §5a.2's RequireWrite
// originally allowed only member/admin, which 403'd every API-key write and
// broke CI clients + the Mode-B smoke test. Keys are admin-minted and gated by
// VULTURE_API_KEYS_ENABLED, so they are a first-class write principal.
func TestRequireWrite_RolePolicy(t *testing.T) {
	cases := []struct {
		role      string
		nilUser   bool
		wantWrite bool
	}{
		{role: "admin", wantWrite: true},
		{role: "member", wantWrite: true},
		{role: "apikey", wantWrite: true}, // CI credential — must not be blocked
		{role: "viewer", wantWrite: false},
		{role: "", wantWrite: false},
		{nilUser: true, wantWrite: false},
	}

	for _, c := range cases {
		name := c.role
		if c.nilUser {
			name = "nil-principal"
		}
		t.Run(name, func(t *testing.T) {
			called := false
			h := RequireWrite(func(http.ResponseWriter, *http.Request) { called = true })

			req := httptest.NewRequest(http.MethodPost, "/api/sources", nil)
			if !c.nilUser {
				req = req.WithContext(context.WithValue(req.Context(), userContextKey,
					&model.User{ID: "u1", Role: c.role}))
			}
			w := httptest.NewRecorder()
			h(w, req)

			if c.wantWrite && (!called || w.Code == http.StatusForbidden) {
				t.Errorf("role %q: POST should be allowed, got status %d (handler called=%v)", c.role, w.Code, called)
			}
			if !c.wantWrite && called {
				t.Errorf("role %q: POST should be rejected, but handler ran", c.role)
			}
		})
	}

	// Method gating (§H1) is unchanged: reads pass through for any principal.
	t.Run("viewer GET passes (method-gated)", func(t *testing.T) {
		called := false
		h := RequireWrite(func(http.ResponseWriter, *http.Request) { called = true })
		req := httptest.NewRequest(http.MethodGet, "/api/audits", nil)
		req = req.WithContext(context.WithValue(req.Context(), userContextKey,
			&model.User{ID: "u1", Role: "viewer"}))
		w := httptest.NewRecorder()
		h(w, req)
		if !called {
			t.Errorf("viewer GET must pass through, got status %d", w.Code)
		}
	})
}
