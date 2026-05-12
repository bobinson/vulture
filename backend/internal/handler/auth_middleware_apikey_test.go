package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

// fakeAuthSvc is a minimal AuthService stub that rejects all JWT tokens.
// It satisfies only what AuthMiddleware.extractUser uses.
type fakeAuthSvc struct{}

func (fakeAuthSvc) Register(req *model.RegisterRequest) (*model.AuthResponse, error) {
	return nil, nil
}
func (fakeAuthSvc) Login(req *model.LoginRequest) (*model.AuthResponse, error) { return nil, nil }
func (fakeAuthSvc) ValidateToken(token string) (*model.User, error) {
	return nil, http.ErrNoCookie
}
func (fakeAuthSvc) ValidateLocalUser() (*model.User, error) { return nil, nil }
func (fakeAuthSvc) IssueLocalAdminToken() (*model.AuthResponse, error) {
	return nil, nil
}

func newMWWithAPIKeySvc(t *testing.T) (*AuthMiddleware, service.APIKeyService) {
	t.Helper()
	svc := service.NewAPIKeyService(repository.NewMockAPIKeyRepo())
	mw := NewAuthMiddleware(fakeAuthSvc{})
	mw.SetAPIKeyService(svc)
	return mw, svc
}

func TestAuthMiddleware_APIKey_Valid(t *testing.T) {
	mw, svc := newMWWithAPIKeySvc(t)
	plaintext, _, err := svc.Create("ci", "u-creator")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	h := mw.Require(func(w http.ResponseWriter, r *http.Request) {
		called = true
		u := getUserFromContext(r)
		if u == nil || u.Role != "apikey" {
			t.Fatalf("expected apikey user, got %+v", u)
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/audits", nil)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	rec := httptest.NewRecorder()
	h(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("api key should authenticate; called=%v code=%d body=%s", called, rec.Code, rec.Body.String())
	}
}

func TestAuthMiddleware_APIKey_Invalid(t *testing.T) {
	mw, _ := newMWWithAPIKeySvc(t)
	h := mw.Require(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called on invalid api key")
	})
	req := httptest.NewRequest("GET", "/api/audits", nil)
	req.Header.Set("Authorization", "Bearer vk_totally_bogus")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_APIKey_NoFallthroughToJWT(t *testing.T) {
	mw, _ := newMWWithAPIKeySvc(t)
	h := mw.Require(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called — vk_ prefix must NOT fall through to JWT")
	})
	req := httptest.NewRequest("GET", "/api/audits", nil)
	// vk_ prefix with invalid value — must NOT be retried as a JWT.
	req.Header.Set("Authorization", "Bearer vk_invalid_should_not_try_jwt")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_APIKey_NilServiceNoVKAuth(t *testing.T) {
	// When apiKeySvc is not set, vk_ tokens fail (don't fall through to JWT).
	mw := NewAuthMiddleware(fakeAuthSvc{})
	h := mw.Require(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called when api key service is nil")
	})
	req := httptest.NewRequest("GET", "/api/audits", nil)
	req.Header.Set("Authorization", "Bearer vk_anything")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_JWT_StillWorksWhenAPIKeysEnabled(t *testing.T) {
	// A non-vk_ bearer goes through the JWT path. fakeAuthSvc rejects all JWTs,
	// so we expect 401 — but NOT a false success from the api-key path.
	mw, _ := newMWWithAPIKeySvc(t)
	h := mw.Require(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("fakeAuthSvc rejects all tokens; handler should never run")
	})
	req := httptest.NewRequest("GET", "/api/audits", nil)
	req.Header.Set("Authorization", "Bearer regular-jwt-token-without-vk-prefix")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
