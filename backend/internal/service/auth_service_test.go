package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// mockUserRepo is a test double for repository.UserRepository.
type mockUserRepo struct {
	createUserFn     func(user *model.User) error
	getUserFn        func(id string) (*model.User, error)
	getUserByEmailFn func(email string) (*model.User, error)
	updateLastLoginFn func(id string) error
	createTeamFn     func(name string) (*model.Team, error)
	getTeamFn        func(id string) (*model.Team, error)
}

func (m *mockUserRepo) CreateUser(user *model.User) error {
	if m.createUserFn != nil {
		return m.createUserFn(user)
	}
	user.ID = "user-123"
	return nil
}

func (m *mockUserRepo) GetUser(id string) (*model.User, error) {
	if m.getUserFn != nil {
		return m.getUserFn(id)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockUserRepo) GetUserByEmail(email string) (*model.User, error) {
	if m.getUserByEmailFn != nil {
		return m.getUserByEmailFn(email)
	}
	return nil, nil
}

func (m *mockUserRepo) UpdateLastLogin(id string) error {
	if m.updateLastLoginFn != nil {
		return m.updateLastLoginFn(id)
	}
	return nil
}

func (m *mockUserRepo) CreateTeam(name string) (*model.Team, error) {
	if m.createTeamFn != nil {
		return m.createTeamFn(name)
	}
	return &model.Team{ID: "team-1", Name: name, CreatedAt: time.Now()}, nil
}

func (m *mockUserRepo) GetTeam(id string) (*model.Team, error) {
	if m.getTeamFn != nil {
		return m.getTeamFn(id)
	}
	return nil, nil
}

const testSecret = "test-secret-key-for-jwt"

// --- Register ---

func TestAuthService_Register_Success(t *testing.T) {
	var createdUser *model.User
	repo := &mockUserRepo{
		getUserByEmailFn: func(email string) (*model.User, error) {
			return nil, nil // no existing user
		},
		createUserFn: func(user *model.User) error {
			user.ID = "new-user-1"
			createdUser = user
			return nil
		},
	}
	svc := NewAuthService(repo, testSecret)

	resp, err := svc.Register(&model.RegisterRequest{
		Email:    "test@example.com",
		Password: "securepass",
		Name:     "Test User",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Token == "" {
		t.Error("expected non-empty token")
	}
	if resp.User.Email != "test@example.com" {
		t.Errorf("user email = %q, want test@example.com", resp.User.Email)
	}
	if resp.User.Name != "Test User" {
		t.Errorf("user name = %q, want Test User", resp.User.Name)
	}
	if resp.User.Role != "user" {
		t.Errorf("user role = %q, want user", resp.User.Role)
	}
	if createdUser == nil {
		t.Fatal("CreateUser was not called")
	}
	if createdUser.PasswordHash == "" {
		t.Error("password hash should not be empty")
	}
	if createdUser.PasswordHash == "securepass" {
		t.Error("password hash should not be plain text")
	}
	if createdUser.TeamID != "" {
		t.Errorf("team_id = %q, want empty for no team", createdUser.TeamID)
	}
}

func TestAuthService_Register_DuplicateEmail(t *testing.T) {
	repo := &mockUserRepo{
		getUserByEmailFn: func(email string) (*model.User, error) {
			return &model.User{ID: "existing-1", Email: email}, nil
		},
	}
	svc := NewAuthService(repo, testSecret)

	_, err := svc.Register(&model.RegisterRequest{
		Email:    "existing@example.com",
		Password: "pass",
		Name:     "Dup User",
	})
	if err == nil {
		t.Fatal("expected error for duplicate email")
	}
	if !strings.Contains(err.Error(), "email already registered") {
		t.Errorf("error = %q, want 'email already registered'", err.Error())
	}
}

func TestAuthService_Register_WithTeam(t *testing.T) {
	teamCreated := false
	repo := &mockUserRepo{
		getUserByEmailFn: func(email string) (*model.User, error) {
			return nil, nil
		},
		createTeamFn: func(name string) (*model.Team, error) {
			teamCreated = true
			if name != "MyTeam" {
				t.Errorf("team name = %q, want MyTeam", name)
			}
			return &model.Team{ID: "team-abc", Name: name, CreatedAt: time.Now()}, nil
		},
		createUserFn: func(user *model.User) error {
			user.ID = "user-with-team"
			if user.TeamID != "team-abc" {
				t.Errorf("user.TeamID = %q, want team-abc", user.TeamID)
			}
			return nil
		},
	}
	svc := NewAuthService(repo, testSecret)

	resp, err := svc.Register(&model.RegisterRequest{
		Email:    "team@example.com",
		Password: "pass",
		Name:     "Team User",
		TeamName: "MyTeam",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !teamCreated {
		t.Error("CreateTeam was not called")
	}
	if resp.User.TeamID != "team-abc" {
		t.Errorf("user.TeamID = %q, want team-abc", resp.User.TeamID)
	}
}

func TestAuthService_Register_TeamCreateError(t *testing.T) {
	repo := &mockUserRepo{
		getUserByEmailFn: func(email string) (*model.User, error) {
			return nil, nil
		},
		createTeamFn: func(name string) (*model.Team, error) {
			return nil, fmt.Errorf("db error")
		},
	}
	svc := NewAuthService(repo, testSecret)

	_, err := svc.Register(&model.RegisterRequest{
		Email:    "test@example.com",
		Password: "pass",
		Name:     "User",
		TeamName: "FailTeam",
	})
	if err == nil {
		t.Fatal("expected error when team creation fails")
	}
	if !strings.Contains(err.Error(), "create team") {
		t.Errorf("error = %q, want to contain 'create team'", err.Error())
	}
}

func TestAuthService_Register_CreateUserError(t *testing.T) {
	repo := &mockUserRepo{
		getUserByEmailFn: func(email string) (*model.User, error) {
			return nil, nil
		},
		createUserFn: func(user *model.User) error {
			return fmt.Errorf("insert failed")
		},
	}
	svc := NewAuthService(repo, testSecret)

	_, err := svc.Register(&model.RegisterRequest{
		Email:    "test@example.com",
		Password: "pass",
		Name:     "User",
	})
	if err == nil {
		t.Fatal("expected error when user creation fails")
	}
	if !strings.Contains(err.Error(), "create user") {
		t.Errorf("error = %q, want to contain 'create user'", err.Error())
	}
}

// --- Login ---

func TestAuthService_Login_Success(t *testing.T) {
	// Pre-register a user to get a proper bcrypt hash
	repo := &mockUserRepo{}
	svc := NewAuthService(repo, testSecret)

	// Register first to get a proper password hash
	var savedHash string
	repo.getUserByEmailFn = func(email string) (*model.User, error) {
		return nil, nil
	}
	repo.createUserFn = func(user *model.User) error {
		user.ID = "login-user-1"
		savedHash = user.PasswordHash
		return nil
	}
	_, err := svc.Register(&model.RegisterRequest{
		Email:    "login@example.com",
		Password: "mypassword",
		Name:     "Login User",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// Now set up the mock for login
	repo.getUserByEmailFn = func(email string) (*model.User, error) {
		return &model.User{
			ID:           "login-user-1",
			Email:        email,
			PasswordHash: savedHash,
			Name:         "Login User",
			Role:         "admin",
		}, nil
	}

	resp, err := svc.Login(&model.LoginRequest{
		Email:    "login@example.com",
		Password: "mypassword",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Token == "" {
		t.Error("expected non-empty token")
	}
	if resp.User.Email != "login@example.com" {
		t.Errorf("user email = %q, want login@example.com", resp.User.Email)
	}
}

func TestAuthService_Login_WrongPassword(t *testing.T) {
	repo := &mockUserRepo{}
	svc := NewAuthService(repo, testSecret)

	// Register to get a hash
	var savedHash string
	repo.getUserByEmailFn = func(email string) (*model.User, error) {
		return nil, nil
	}
	repo.createUserFn = func(user *model.User) error {
		user.ID = "u1"
		savedHash = user.PasswordHash
		return nil
	}
	_, _ = svc.Register(&model.RegisterRequest{
		Email: "wp@example.com", Password: "correct", Name: "U",
	})

	// Login with wrong password
	repo.getUserByEmailFn = func(email string) (*model.User, error) {
		return &model.User{
			ID: "u1", Email: email, PasswordHash: savedHash,
		}, nil
	}

	_, err := svc.Login(&model.LoginRequest{
		Email: "wp@example.com", Password: "wrong",
	})
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if !strings.Contains(err.Error(), "invalid credentials") {
		t.Errorf("error = %q, want 'invalid credentials'", err.Error())
	}
}

func TestAuthService_Login_NonexistentUser(t *testing.T) {
	repo := &mockUserRepo{
		getUserByEmailFn: func(email string) (*model.User, error) {
			return nil, nil // not found
		},
	}
	svc := NewAuthService(repo, testSecret)

	_, err := svc.Login(&model.LoginRequest{
		Email: "nobody@example.com", Password: "pass",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
	if !strings.Contains(err.Error(), "invalid credentials") {
		t.Errorf("error = %q, want 'invalid credentials'", err.Error())
	}
}

func TestAuthService_Login_RepoError(t *testing.T) {
	repo := &mockUserRepo{
		getUserByEmailFn: func(email string) (*model.User, error) {
			return nil, fmt.Errorf("db connection lost")
		},
	}
	svc := NewAuthService(repo, testSecret)

	_, err := svc.Login(&model.LoginRequest{
		Email: "err@example.com", Password: "pass",
	})
	if err == nil {
		t.Fatal("expected error for repo failure")
	}
}

// --- ValidateToken ---

func TestAuthService_ValidateToken_Valid(t *testing.T) {
	repo := &mockUserRepo{
		getUserByEmailFn: func(email string) (*model.User, error) {
			return nil, nil
		},
		createUserFn: func(user *model.User) error {
			user.ID = "valid-user-1"
			return nil
		},
	}
	svc := NewAuthService(repo, testSecret)

	// Register to get a token
	resp, err := svc.Register(&model.RegisterRequest{
		Email: "valid@example.com", Password: "pass", Name: "Valid",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// Set up GetUser for validation
	repo.getUserFn = func(id string) (*model.User, error) {
		if id != "valid-user-1" {
			t.Errorf("GetUser called with %q, want valid-user-1", id)
		}
		return &model.User{
			ID: "valid-user-1", Email: "valid@example.com", Name: "Valid",
		}, nil
	}

	user, err := svc.ValidateToken(resp.Token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.ID != "valid-user-1" {
		t.Errorf("user.ID = %q, want valid-user-1", user.ID)
	}
}

func TestAuthService_ValidateToken_InvalidFormat(t *testing.T) {
	repo := &mockUserRepo{}
	svc := NewAuthService(repo, testSecret)

	_, err := svc.ValidateToken("not-a-jwt")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "invalid token format") {
		t.Errorf("error = %q, want 'invalid token format'", err.Error())
	}
}

func TestAuthService_ValidateToken_InvalidSignature(t *testing.T) {
	repo := &mockUserRepo{
		getUserByEmailFn: func(email string) (*model.User, error) {
			return nil, nil
		},
		createUserFn: func(user *model.User) error {
			user.ID = "u1"
			return nil
		},
	}
	svc := NewAuthService(repo, testSecret)

	resp, err := svc.Register(&model.RegisterRequest{
		Email: "sig@example.com", Password: "pass", Name: "Sig",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// Tamper with the signature
	parts := strings.Split(resp.Token, ".")
	tamperedToken := parts[0] + "." + parts[1] + ".invalidsignature"

	_, err = svc.ValidateToken(tamperedToken)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
	if !strings.Contains(err.Error(), "invalid token signature") {
		t.Errorf("error = %q, want 'invalid token signature'", err.Error())
	}
}

func TestAuthService_ValidateToken_Expired(t *testing.T) {
	repo := &mockUserRepo{}
	svc := NewAuthService(repo, testSecret).(*authService)

	// Build a token with an expired time
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := map[string]interface{}{
		"sub":     "expired-user",
		"email":   "expired@example.com",
		"role":    "admin",
		"team_id": "",
		"iat":     time.Now().Add(-48 * time.Hour).Unix(),
		"exp":     time.Now().Add(-24 * time.Hour).Unix(), // expired 24h ago
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	sigInput := header + "." + payload
	signature := svc.sign(sigInput)
	expiredToken := sigInput + "." + signature

	_, err := svc.ValidateToken(expiredToken)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !strings.Contains(err.Error(), "token expired") {
		t.Errorf("error = %q, want 'token expired'", err.Error())
	}
}

func TestAuthService_ValidateToken_UserNotFound(t *testing.T) {
	repo := &mockUserRepo{
		getUserByEmailFn: func(email string) (*model.User, error) {
			return nil, nil
		},
		createUserFn: func(user *model.User) error {
			user.ID = "gone-user"
			return nil
		},
		getUserFn: func(id string) (*model.User, error) {
			return nil, nil // user no longer exists
		},
	}
	svc := NewAuthService(repo, testSecret)

	resp, err := svc.Register(&model.RegisterRequest{
		Email: "gone@example.com", Password: "pass", Name: "Gone",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	_, err = svc.ValidateToken(resp.Token)
	if err == nil {
		t.Fatal("expected error for deleted user")
	}
	if !strings.Contains(err.Error(), "user not found") {
		t.Errorf("error = %q, want 'user not found'", err.Error())
	}
}

// --- Token format ---

func TestAuthService_TokenFormat(t *testing.T) {
	repo := &mockUserRepo{
		getUserByEmailFn: func(email string) (*model.User, error) {
			return nil, nil
		},
		createUserFn: func(user *model.User) error {
			user.ID = "fmt-user"
			return nil
		},
	}
	svc := NewAuthService(repo, testSecret)

	resp, err := svc.Register(&model.RegisterRequest{
		Email: "fmt@example.com", Password: "pass", Name: "Fmt",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	parts := strings.Split(resp.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header["alg"] != "HS256" {
		t.Errorf("alg = %q, want HS256", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("typ = %q, want JWT", header["typ"])
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["email"] != "fmt@example.com" {
		t.Errorf("email = %v, want fmt@example.com", payload["email"])
	}
	if payload["sub"] != "fmt-user" {
		t.Errorf("sub = %v, want fmt-user", payload["sub"])
	}
	if payload["role"] != "user" {
		t.Errorf("role = %v, want user", payload["role"])
	}
	exp, ok := payload["exp"].(float64)
	if !ok {
		t.Fatal("exp claim missing or not a number")
	}
	if int64(exp) <= time.Now().Unix() {
		t.Error("token should not be expired immediately after creation")
	}
}
