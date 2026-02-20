package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

// mockUserRepo implements repository.UserRepository for testing.
type mockUserRepo struct {
	users map[string]*model.User
	teams map[string]*model.Team
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{
		users: make(map[string]*model.User),
		teams: make(map[string]*model.Team),
	}
}

func (r *mockUserRepo) CreateUser(user *model.User) error {
	user.ID = "test-user-id"
	r.users[user.Email] = user
	return nil
}

func (r *mockUserRepo) GetUser(id string) (*model.User, error) {
	for _, u := range r.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, nil
}

func (r *mockUserRepo) GetUserByEmail(email string) (*model.User, error) {
	return r.users[email], nil
}

func (r *mockUserRepo) UpdateLastLogin(id string) error {
	return nil
}

func (r *mockUserRepo) CreateTeam(name string) (*model.Team, error) {
	team := &model.Team{
		ID:        "test-team-id",
		Name:      name,
		CreatedAt: time.Now().UTC(),
	}
	r.teams[team.ID] = team
	return team, nil
}

func (r *mockUserRepo) GetTeam(id string) (*model.Team, error) {
	return r.teams[id], nil
}

func TestAuthRegister(t *testing.T) {
	repo := newMockUserRepo()
	svc := service.NewAuthService(repo, "test-secret-key-12345")
	h := NewAuthHandler(svc)

	body := `{"email":"test@example.com","password":"secure12345","name":"Test User"}`
	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Register(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp model.AuthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token")
	}
	if resp.User.Email != "test@example.com" {
		t.Fatalf("expected test@example.com, got %s", resp.User.Email)
	}
	if resp.User.Name != "Test User" {
		t.Fatalf("expected Test User, got %s", resp.User.Name)
	}
}

func TestAuthRegisterMissingFields(t *testing.T) {
	repo := newMockUserRepo()
	svc := service.NewAuthService(repo, "test-secret-key-12345")
	h := NewAuthHandler(svc)

	body := `{"email":"test@example.com"}`
	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Register(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAuthRegisterShortPassword(t *testing.T) {
	repo := newMockUserRepo()
	svc := service.NewAuthService(repo, "test-secret-key-12345")
	h := NewAuthHandler(svc)

	body := `{"email":"test@example.com","password":"short","name":"Test"}`
	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Register(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAuthLogin(t *testing.T) {
	repo := newMockUserRepo()
	svc := service.NewAuthService(repo, "test-secret-key-12345")
	h := NewAuthHandler(svc)

	// First register
	regBody := `{"email":"login@example.com","password":"secure12345","name":"Login Test"}`
	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBufferString(regBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Register(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register failed: %d", w.Code)
	}

	// Then login
	loginBody := `{"email":"login@example.com","password":"secure12345"}`
	req = httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp model.AuthResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestAuthLoginInvalidPassword(t *testing.T) {
	repo := newMockUserRepo()
	svc := service.NewAuthService(repo, "test-secret-key-12345")
	h := NewAuthHandler(svc)

	// Register
	regBody := `{"email":"bad@example.com","password":"secure12345","name":"Bad Login"}`
	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBufferString(regBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Register(w, req)

	// Login with wrong password
	loginBody := `{"email":"bad@example.com","password":"wrongpassword"}`
	req = httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuthMe(t *testing.T) {
	repo := newMockUserRepo()
	svc := service.NewAuthService(repo, "test-secret-key-12345")
	h := NewAuthHandler(svc)
	mw := NewAuthMiddleware(svc)

	// Register to get a token
	regBody := `{"email":"me@example.com","password":"secure12345","name":"Me Test"}`
	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBufferString(regBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Register(w, req)

	var resp model.AuthResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// Use token to call /me
	req = httptest.NewRequest("GET", "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)
	w = httptest.NewRecorder()
	mw.Require(h.Me)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var user model.User
	json.NewDecoder(w.Body).Decode(&user)
	if user.Email != "me@example.com" {
		t.Fatalf("expected me@example.com, got %s", user.Email)
	}
}

func TestAuthMeNoToken(t *testing.T) {
	repo := newMockUserRepo()
	svc := service.NewAuthService(repo, "test-secret-key-12345")
	h := NewAuthHandler(svc)
	mw := NewAuthMiddleware(svc)

	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	w := httptest.NewRecorder()
	mw.Require(h.Me)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuthMiddlewareOptional(t *testing.T) {
	repo := newMockUserRepo()
	svc := service.NewAuthService(repo, "test-secret-key-12345")
	mw := NewAuthMiddleware(svc)

	// Without token - should still call handler
	called := false
	handler := mw.Optional(func(w http.ResponseWriter, r *http.Request) {
		called = true
		user := getUserFromContext(r)
		if user != nil {
			t.Fatal("expected no user in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Fatal("handler should have been called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRegisterWithTeam(t *testing.T) {
	repo := newMockUserRepo()
	svc := service.NewAuthService(repo, "test-secret-key-12345")
	h := NewAuthHandler(svc)

	body := `{"email":"team@example.com","password":"secure12345","name":"Team User","team_name":"My Team"}`
	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Register(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp model.AuthResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.User.TeamID == "" {
		t.Fatal("expected non-empty team_id")
	}
}
