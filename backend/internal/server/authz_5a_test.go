package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"

	"golang.org/x/crypto/bcrypt"
)

// 0065 Phase 5a — authorization guardrails (RED baseline).
//
// These httptest-level E2E tests drive the REAL mux (NewWithRegistry) in
// Mode B (LocalMode=false, VULTURE_ALLOW_OPEN_REGISTRATION unset) and pin the
// §5a contract:
//
//   5a.1  open self-registration is closed by default in Mode B (403), with an
//         admin-gated provisioning path (/api/admin/users) that an admin may
//         use and a member may not.
//   5a.2  writes are role-gated but reads are NOT: a viewer can GET /api/audits
//         but is forbidden (403) from POST /api/sources and POST /api/audits;
//         a member may write. (§H1 method-gated RequireWrite.)
//
// They are RED against current code, which (a) always wires open registration,
// (b) has no /api/admin/users route, and (c) applies no role gate to the write
// endpoints (any authenticated principal, including a viewer, may POST).

const authz5aPassword = "correct-horse-battery-staple"

// newModeBServer builds the production mux in Mode B on a throwaway SQLite DB
// and returns the handler plus a user repo (a second handle on the same file)
// for seeding principals with explicit roles.
func newModeBServer(t *testing.T) (http.Handler, repository.UserRepository, string) {
	t.Helper()

	// Mode B with open registration NOT enabled and no docker supervisor.
	t.Setenv("VULTURE_ALLOW_OPEN_REGISTRATION", "false")
	t.Setenv("VULTURE_DISABLE_SUPERVISOR", "true")

	if err := ConfigureTrustedProxies(nil); err != nil {
		t.Fatalf("ConfigureTrustedProxies: %v", err)
	}
	t.Cleanup(func() { _ = ConfigureTrustedProxies(nil) })

	dbPath := filepath.Join(t.TempDir(), "authz5a.db")
	secret := strings.Repeat("k", 40) // >= 32 bytes for HS256 (Mode B requirement)
	cfg := &config.Config{
		Port:       "0",
		ListenAddr: "127.0.0.1:0",
		DBPath:     dbPath,
		LocalMode:  false,
		JWTSecret:  secret,
		AgentToken: "agent-token-for-mode-b", // Mode B refuses to start without one
		Agents:     map[string]config.AgentConfig{},
	}

	// nil registry keeps the build docker-free (no supervisor / stagerouter).
	srv, err := NewWithRegistry(cfg, nil)
	if err != nil {
		t.Fatalf("NewWithRegistry: %v", err)
	}

	// Second handle on the same SQLite file to seed users with explicit roles.
	dbRepo, err := repository.NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("open user db: %v", err)
	}
	userRepo := repository.NewSQLiteUserRepo(dbRepo.DB())

	return srv.Handler(), userRepo, secret
}

// seedUserToken creates a user with the given role and returns a valid JWT for
// it. The token role is irrelevant: authMW re-loads the user DB-fresh on every
// request, so the persisted role is what the guards see.
func seedUserToken(t *testing.T, userRepo repository.UserRepository, secret, email, role string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(authz5aPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	u := &model.User{
		Email:        email,
		PasswordHash: string(hash),
		Name:         role + " user",
		Role:         role,
		CreatedAt:    time.Now().UTC(),
	}
	if err := userRepo.CreateUser(u); err != nil {
		t.Fatalf("create %s user: %v", role, err)
	}
	authSvc := service.NewAuthService(userRepo, secret)
	resp, err := authSvc.Login(&model.LoginRequest{Email: email, Password: authz5aPassword})
	if err != nil {
		t.Fatalf("login %s: %v", role, err)
	}
	return resp.Token
}

// doJSON issues a request against the mux and returns the status code.
func doJSON(t *testing.T, h http.Handler, method, path, token string, body any) int {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = "127.0.0.1:55555"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// 5a.1 — open self-registration is closed by default in Mode B.
func TestAuthz5a_ModeB_RegistrationDisabled(t *testing.T) {
	h, _, _ := newModeBServer(t)

	code := doJSON(t, h, http.MethodPost, "/api/auth/register", "", model.RegisterRequest{
		Email:    "newcomer@example.com",
		Password: "a-strong-password-123",
		Name:     "Newcomer",
	})
	if code != http.StatusForbidden {
		t.Fatalf("Mode B POST /api/auth/register: got %d, want 403 (open registration must be closed by default)", code)
	}
}

// 5a.1 — admin-gated provisioning: an admin may create users, a member may not.
func TestAuthz5a_AdminProvisioning(t *testing.T) {
	h, userRepo, secret := newModeBServer(t)
	adminToken := seedUserToken(t, userRepo, secret, "admin@example.com", "admin")
	memberToken := seedUserToken(t, userRepo, secret, "member@example.com", "member")

	// Admin can provision a new user.
	code := doJSON(t, h, http.MethodPost, "/api/admin/users", adminToken, model.RegisterRequest{
		Email:    "provisioned@example.com",
		Password: "a-strong-password-123",
		Name:     "Provisioned",
	})
	if code != http.StatusCreated {
		t.Fatalf("admin POST /api/admin/users: got %d, want 201", code)
	}

	// Member cannot.
	code = doJSON(t, h, http.MethodPost, "/api/admin/users", memberToken, model.RegisterRequest{
		Email:    "sneaky@example.com",
		Password: "a-strong-password-123",
		Name:     "Sneaky",
	})
	if code != http.StatusForbidden {
		t.Fatalf("member POST /api/admin/users: got %d, want 403 (admin-only)", code)
	}
}

// 5a.2 (§H1) — writes are role-gated, reads are not. A viewer reads but cannot
// write; a member writes.
func TestAuthz5a_WriteGuardMethodGated(t *testing.T) {
	h, userRepo, secret := newModeBServer(t)
	viewerToken := seedUserToken(t, userRepo, secret, "viewer@example.com", "viewer")
	memberToken := seedUserToken(t, userRepo, secret, "member2@example.com", "member")

	// Viewer GET /api/audits — reads must stay open (method-gated guard).
	if code := doJSON(t, h, http.MethodGet, "/api/audits", viewerToken, nil); code != http.StatusOK {
		t.Fatalf("viewer GET /api/audits: got %d, want 200 (reads must not be blocked)", code)
	}

	// Viewer writes — forbidden.
	if code := doJSON(t, h, http.MethodPost, "/api/sources", viewerToken, map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("viewer POST /api/sources: got %d, want 403", code)
	}
	if code := doJSON(t, h, http.MethodPost, "/api/audits", viewerToken, map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("viewer POST /api/audits: got %d, want 403", code)
	}

	// Member writes — the guard must admit the request (not 403/401). The
	// handler may still 4xx on the empty body; we only assert the role gate
	// let it through.
	if code := doJSON(t, h, http.MethodPost, "/api/sources", memberToken, map[string]string{}); code == http.StatusForbidden || code == http.StatusUnauthorized {
		t.Fatalf("member POST /api/sources: got %d, want the write guard to admit a member", code)
	}
	if code := doJSON(t, h, http.MethodPost, "/api/audits", memberToken, map[string]string{}); code == http.StatusForbidden || code == http.StatusUnauthorized {
		t.Fatalf("member POST /api/audits: got %d, want the write guard to admit a member", code)
	}
}
