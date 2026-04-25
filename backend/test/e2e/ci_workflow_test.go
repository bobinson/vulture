//go:build e2e

package e2e

// Feature 0031, Task 15 — End-to-end test for the simulated CI workflow.
//
// Verifies the full "CI machine submits an audit via API key" path:
//   1. Admin obtains JWT via local-session.
//   2. Admin POSTs /api/api-keys to mint a vk_xxx key.
//   3. CI client POSTs /api/sources using the API key (Bearer vk_xxx).
//   4. CI client POSTs /api/audits using the API key, including a webhook_url.
//   5. CI client polls /api/audits/{id} (the cli `--wait` behavior).
//
// Also verifies negative paths:
//   - /api/api-keys is not registered when VULTURE_API_KEYS_ENABLED is unset.
//   - A revoked API key is rejected with 401.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/vulture/backend/internal/config"
)

// ciTestConfig produces a Mode-B style config: real auth (LocalMode=false)
// with API keys enabled. Mirrors what a centralized server deployment
// would look like — LocalMode auth-bypass would mask API-key validation
// failures and is therefore inappropriate for testing the API-key path.
func ciTestConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "vulture_ci_test.db")
	cfg := &config.Config{
		Port:           "0",
		DBPath:         dbPath,
		LocalMode:      false,
		APIKeysEnabled: true,
		JWTSecret:      "test-secret-for-e2e-ci",
		Agents: map[string]config.AgentConfig{
			"chaos": {Name: "Chaos Engineering", Type: "chaos", URL: ""},
			"owasp": {Name: "OWASP", Type: "owasp", URL: ""},
		},
	}
	return cfg, dbPath
}

// promoteUserToAdmin opens the SQLite test DB and sets the named user's
// role to "admin" because the API-key admin guard
// (api_key_handler.go:121) requires Role == "admin" and /api/auth/register
// always sets role=user. Mirrors the real Mode-B deployment bootstrap step
// described in docs/guides/central_server_deployment.md.
func promoteUserToAdmin(t *testing.T, dbPath, email string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	res, err := db.Exec(`UPDATE users SET role = 'admin' WHERE email = ?`, email)
	if err != nil {
		t.Fatalf("promote admin: %v", err)
	}
	rows, _ := res.RowsAffected()
	if rows != 1 {
		t.Fatalf("promote admin: expected 1 row updated for %q, got %d", email, rows)
	}
}

// registerAndLogin registers a new user via /api/auth/register, optionally
// promotes them to admin via direct DB write, and returns the JWT from
// /api/auth/login.
func registerAndLogin(t *testing.T, addr, dbPath, email, password string, makeAdmin bool) string {
	t.Helper()
	resp, err := httpPost(addr, "/api/auth/register", map[string]string{
		"email":    email,
		"password": password,
		"name":     "Test User",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register: status %d, body %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	if makeAdmin {
		promoteUserToAdmin(t, dbPath, email)
	}

	resp, err = httpPost(addr, "/api/auth/login", map[string]string{
		"email":    email,
		"password": password,
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	var login struct {
		Token string `json:"token"`
	}
	readJSON(t, resp, &login)
	if login.Token == "" {
		t.Fatal("login returned empty token")
	}
	return login.Token
}

func httpPostWithAuth(addr, path, token string, body interface{}) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequest("POST", "http://"+addr+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return http.DefaultClient.Do(req)
}

func httpGetWithAuth(addr, path, token string) (*http.Response, error) {
	req, err := http.NewRequest("GET", "http://"+addr+path, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return http.DefaultClient.Do(req)
}

func httpDeleteWithAuth(addr, path, token string) (*http.Response, error) {
	req, err := http.NewRequest("DELETE", "http://"+addr+path, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return http.DefaultClient.Do(req)
}

// TestCIWorkflow_BootstrapAndUseAPIKey is the happy-path simulated CI run.
func TestCIWorkflow_BootstrapAndUseAPIKey(t *testing.T) {
	cfg, dbPath := ciTestConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	// --- Step 1: bootstrap admin (mirrors central_server_deployment.md).
	adminToken := registerAndLogin(t, addr, dbPath, "admin@example.test", "admin-password-1", true)

	// --- Step 2: admin creates an API key for the CI client.
	resp, err := httpPostWithAuth(addr, "/api/api-keys", adminToken, map[string]string{
		"name": "ci-github-actions",
	})
	if err != nil {
		t.Fatalf("POST /api/api-keys: %v", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /api/api-keys: status %d, body %s", resp.StatusCode, body)
	}
	var keyResp struct {
		ID     string `json:"id"`
		Prefix string `json:"prefix"`
		Name   string `json:"name"`
		Key    string `json:"key"`
	}
	readJSON(t, resp, &keyResp)
	if !strings.HasPrefix(keyResp.Key, "vk_") {
		t.Fatalf("expected key with vk_ prefix, got %q", keyResp.Key)
	}
	if keyResp.Name != "ci-github-actions" {
		t.Fatalf("expected name=ci-github-actions, got %q", keyResp.Name)
	}
	apiKey := keyResp.Key
	apiKeyID := keyResp.ID

	// --- Step 3: CI client uses the API key to register a source.
	srcDir := createTestSourceDir(t)
	resp, err = httpPostWithAuth(addr, "/api/sources", apiKey, map[string]string{
		"type": "local",
		"path": srcDir,
	})
	if err != nil {
		t.Fatalf("POST /api/sources with API key: %v", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /api/sources: status %d, body %s", resp.StatusCode, body)
	}
	var src struct {
		ID string `json:"id"`
	}
	readJSON(t, resp, &src)
	if src.ID == "" {
		t.Fatal("expected non-empty source id from API-key-authenticated request")
	}

	// --- Step 4: CI client uses the API key to start an audit with a webhook.
	// We don't require the webhook to fire (no real agents in this test),
	// only that the audit-creation endpoint accepts the webhook_url field.
	var webhookHits int32
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&webhookHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookSrv.Close()

	resp, err = httpPostWithAuth(addr, "/api/audits", apiKey, map[string]interface{}{
		"source_id":   src.ID,
		"types":       []string{"chaos"},
		"config":      map[string]interface{}{},
		"webhook_url": webhookSrv.URL,
	})
	if err != nil {
		t.Fatalf("POST /api/audits with API key + webhook: %v", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /api/audits: status %d, body %s", resp.StatusCode, body)
	}
	var audit struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	readJSON(t, resp, &audit)
	if audit.ID == "" {
		t.Fatal("expected non-empty audit id")
	}

	// --- Step 5: CI client polls audit status (the cli's --wait behavior).
	// We allow a brief poll; with no real agents the audit will sit in
	// pending/running. We just verify the GET path works under API-key auth.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r, err := httpGetWithAuth(addr, "/api/audits/"+audit.ID, apiKey)
		if err != nil {
			t.Fatalf("GET /api/audits/{id} with API key: %v", err)
		}
		if r.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			t.Fatalf("GET /api/audits/{id}: status %d, body %s", r.StatusCode, body)
		}
		r.Body.Close()
		time.Sleep(100 * time.Millisecond)
	}

	// --- Step 6: revoke the API key, then verify it can no longer authenticate.
	resp, err = httpDeleteWithAuth(addr, "/api/api-keys/"+apiKeyID, adminToken)
	if err != nil {
		t.Fatalf("DELETE /api/api-keys: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /api/api-keys: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Subsequent requests with the revoked key must return 401.
	resp, err = httpGetWithAuth(addr, "/api/audits/"+audit.ID, apiKey)
	if err != nil {
		t.Fatalf("GET after revoke: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after revoke, got %d", resp.StatusCode)
	}
}

// TestCIWorkflow_APIKeyRoutesGatedByEnvFlag verifies that when
// APIKeysEnabled=false the /api/api-keys routes are NOT registered. This
// preserves the dev-local backwards compat invariant from the plan.
func TestCIWorkflow_APIKeyRoutesGatedByEnvFlag(t *testing.T) {
	cfg := testConfig(t) // APIKeysEnabled defaults to false
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, err := httpPost(addr, "/api/api-keys", map[string]string{"name": "should-fail"})
	if err != nil {
		t.Fatalf("POST /api/api-keys: %v", err)
	}
	defer resp.Body.Close()
	// When the route is not registered, http.ServeMux returns 404.
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 404 (route unregistered), got %d, body %s", resp.StatusCode, body)
	}
}

// TestCIWorkflow_InvalidAPIKeyRejected verifies the auth middleware
// rejects a malformed or unknown vk_-prefixed key with 401.
func TestCIWorkflow_InvalidAPIKeyRejected(t *testing.T) {
	cfg, _ := ciTestConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, err := httpGetWithAuth(addr, "/api/audits", "vk_thiskeydoesnotexistanywhere0000000000000000")
	if err != nil {
		t.Fatalf("GET /api/audits: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 for unknown API key, got %d, body %s", resp.StatusCode, body)
	}
}
