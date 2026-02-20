package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

// setupLocalMode creates an auth service with a seeded local user and returns
// the auth handler, auth middleware, and auth service for testing.
func setupLocalMode(t *testing.T) (*AuthHandler, *AuthMiddleware, service.AuthService) {
	t.Helper()
	repo := newMockUserRepo()
	svc := service.NewAuthService(repo, "test-secret-key-12345")

	// Seed local user
	_, err := svc.Register(&model.RegisterRequest{
		Email:    "admin@vulture.local",
		Password: "REDACTED-DEV-PW",
		Name:     "Local Admin",
	})
	if err != nil {
		t.Fatalf("seed local user: %v", err)
	}

	h := NewAuthHandler(svc)
	mw := NewAuthMiddleware(svc)
	return h, mw, svc
}

// --- Local session endpoint ---

func TestLocalMode_LocalSession_ReturnsTokenAndUser(t *testing.T) {
	h, _, _ := setupLocalMode(t)
	h.SetLocalMode(true)

	req := httptest.NewRequest("GET", "/api/auth/local-session", nil)
	w := httptest.NewRecorder()
	h.LocalSession(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp model.AuthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token")
	}
	if resp.User.Email != "admin@vulture.local" {
		t.Fatalf("expected admin@vulture.local, got %s", resp.User.Email)
	}
	if resp.User.Name != "Local Admin" {
		t.Fatalf("expected Local Admin, got %s", resp.User.Name)
	}
}

func TestLocalMode_LocalSession_DisabledReturns404(t *testing.T) {
	h, _, _ := setupLocalMode(t)
	// local mode NOT enabled (default false)

	req := httptest.NewRequest("GET", "/api/auth/local-session", nil)
	w := httptest.NewRecorder()
	h.LocalSession(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- Auth middleware in local mode ---

func TestLocalMode_Middleware_AutoInjectsUserWithoutToken(t *testing.T) {
	_, mw, _ := setupLocalMode(t)
	mw.SetLocalMode(true)

	var gotUser *model.User
	handler := mw.Require(func(w http.ResponseWriter, r *http.Request) {
		gotUser = getUserFromContext(r)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/agents", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if gotUser == nil {
		t.Fatal("expected user in context")
	}
	if gotUser.Email != "admin@vulture.local" {
		t.Fatalf("expected admin@vulture.local, got %s", gotUser.Email)
	}
}

func TestLocalMode_Middleware_StillAcceptsValidToken(t *testing.T) {
	h, mw, _ := setupLocalMode(t)
	h.SetLocalMode(true)
	mw.SetLocalMode(true)

	// Get a token via local session
	req := httptest.NewRequest("GET", "/api/auth/local-session", nil)
	w := httptest.NewRecorder()
	h.LocalSession(w, req)

	var resp model.AuthResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// Use the token — should work as before
	var gotUser *model.User
	handler := mw.Require(func(w http.ResponseWriter, r *http.Request) {
		gotUser = getUserFromContext(r)
		w.WriteHeader(http.StatusOK)
	})

	req = httptest.NewRequest("GET", "/api/agents", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)
	w = httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotUser == nil {
		t.Fatal("expected user in context")
	}
}

// --- Normal mode (local mode disabled) ---

func TestNormalMode_Middleware_RejectsWithoutToken(t *testing.T) {
	_, mw, _ := setupLocalMode(t)
	// local mode NOT enabled (default)

	handler := mw.Require(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called without auth")
	})

	req := httptest.NewRequest("GET", "/api/agents", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestNormalMode_Middleware_AcceptsValidToken(t *testing.T) {
	_, mw, svc := setupLocalMode(t)

	// Login to get token
	resp, err := svc.Login(&model.LoginRequest{
		Email:    "admin@vulture.local",
		Password: "REDACTED-DEV-PW",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	var gotUser *model.User
	handler := mw.Require(func(w http.ResponseWriter, r *http.Request) {
		gotUser = getUserFromContext(r)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/agents", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotUser == nil {
		t.Fatal("expected user in context")
	}
}

// --- Config integration ---

func TestLocalMode_ConfigFlag_PropagatedToComponents(t *testing.T) {
	h, mw, _ := setupLocalMode(t)

	// Verify default is false
	if h.localMode {
		t.Fatal("expected localMode default to be false")
	}

	// Enable local mode
	h.SetLocalMode(true)
	mw.SetLocalMode(true)

	if !h.localMode {
		t.Fatal("expected localMode to be true after SetLocalMode(true)")
	}
}
