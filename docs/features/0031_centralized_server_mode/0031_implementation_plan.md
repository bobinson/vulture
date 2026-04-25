# 0031 Centralized Audit Server with CI Integration Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add API-key auth, webhook callbacks, per-source git credentials, and CI-friendly CLI flags so that Vulture can run as a **centralized audit server** that CI pipelines (and desktop users) submit scans to. The current single-host dev mode must continue to work unchanged.

**Core design principle:** every new capability is **additive** and **opt-in**. A fresh `docker compose up` on a developer's laptop behaves exactly as it does today. Centralization is enabled by env flags and optional request fields; nothing is forced.

**Tech Stack:** Go backend (`lib/pq`, `net/http`), Python agents unchanged, Vulture CLI (Go), Postgres/SQLite, optional Neon. All existing dependencies; no new runtime requirements.

---

## Problem statement

Today Vulture has two working deployment modes:

1. **Single-host dev:** `docker compose up` — everything local, user at a browser. (Works.)
2. **Writer / reader split (feature 0030):** desktop runs writer, VM runs readonly viewer, shared remote DB. (Works.)

Neither is CI-friendly. CI needs:
- Machine-to-machine auth (not JWT-on-user-session)
- Submit a scan via HTTP, get results via HTTP, exit with status code
- No long-lived processes or docker-compose-in-CI
- Minimal per-run cost

This plan adds CI-friendly capabilities to the existing backend so the **same binary**, **same compose file**, **same DB schema** serves three modes:

| Mode | Who runs it | Config | Works today? |
|------|-------------|--------|--------------|
| A: Dev-local | Developer laptop | `docker compose up` | ✅ unchanged |
| B: Centralized server | Ops team (VM) | Same compose, DSN → remote DB, API keys enabled | 🚧 needs this plan |
| C: Read-only viewer VM | Ops team (VM) | `docker-compose.readonly.yml` (feature 0030) | ✅ shipped |
| D: CI/CD client | Any CI | `vulture scan --api-key X --server Y --wait` | 🚧 needs this plan |

---

## Target architecture

```
┌────────────────────┐         ┌──────────────────────────┐        ┌──────────────┐
│ CI runners         │         │ Central server           │        │ Neon DB      │
│ (ephemeral)        │         │ (persistent VM)          │        │ (persistent) │
│ ─────────────────  │         │ ──────────────────────── │        │ ──────────── │
│ vulture scan       │─HTTPS──▶│ backend + 9 agents       │───────▶│ findings     │
│   --api-key X      │ POST    │ clones git URL directly  │        │ memories     │
│   --wait           │◀─SSE────│ streams progress         │◀───────│ lineage      │
│   exit code        │ poll    │ optional webhook on done │        │ ...          │
└────────────────────┘         └────────────┬─────────────┘        └──────▲───────┘
                                            │ WRITE                       │ READ
                               ┌────────────┘                             │
┌────────────────────┐         │                                 ┌────────┴────────┐
│ Desktop dev        │─HTTPS──▶│                                 │ Viewer VM       │
│ (via CLI or UI)    │         │                                 │ readonly backend│
└────────────────────┘         │                                 │ + React SPA     │
                                                                 └─────────────────┘
```

**Same central server serves both CI and human users.** The viewer VM from feature 0030 is optional — without it, users hit the central server's UI directly.

### What changes vs today

- Backend gets a new auth path (API keys) alongside existing JWT-user auth.
- Backend gets optional webhook dispatch on audit completion.
- Source service accepts per-request git credentials and isolates clones per run.
- CLI learns `--api-key`, `--wait`, `--output`, `--exit-on`, `--webhook`, plus an `api-key` subcommand.
- New docs + CI templates.

### What does NOT change

- JWT user auth (existing users keep logging in as before).
- Docker Compose topology (same services, same ports).
- Database schema existing tables (only additions via migrations 011-012).
- Agent behaviour (agents never touch API keys; backend still the only DB writer).
- Single-host dev mode behaviour (no required env vars; all new features opt-in).

---

## File Structure

### New files

```
backend/
  internal/
    model/
      api_key.go                 # APIKey struct, hashing/verification
      webhook.go                 # WebhookConfig, WebhookDelivery
    repository/
      api_key_repo.go            # Interface
      postgres_api_key_repo.go
      sqlite_api_key_repo.go
      mock_api_key_repo.go
      webhook_repo.go            # Interface
      postgres_webhook_repo.go
      sqlite_webhook_repo.go
    service/
      api_key_service.go         # Create, verify, revoke, list
      api_key_service_test.go
      webhook_service.go         # Dispatch with retry + HMAC
      webhook_service_test.go
    handler/
      api_key_handler.go         # CRUD endpoints
      api_key_handler_test.go
  migrations/
    011_api_keys.sql             # api_keys table
    012_audit_webhooks.sql       # audit_webhook_deliveries table
cli/
  apikey.go                      # vulture api-key subcommand
.github/
  workflow-examples/
    vulture-audit.yml            # GitHub Actions template
docs/
  features/0031_centralized_server_mode/
    0031_implementation_plan.md  # (this file)
    0031_implementation_status.md
    0031_rollback_plan.md
  guides/
    central_server_deployment.md # VM setup, TLS, firewall
    ci_integration.md            # GHA + GitLab + Jenkins examples
```

### Modified files

```
backend/
  internal/
    handler/
      auth_middleware.go         # Accept API-key bearer tokens alongside JWT
      audit_handler.go           # Accept webhook_url in POST body; record api_key_id
      source_handler.go          # Accept git_credentials; per-run dirs
    service/
      audit_service.go           # Call webhook service on completion
      source_service.go          # Per-run source dirs; forward credentials
      stream_service.go          # No-op (kept on purpose)
    server/
      server.go                  # Register api-key routes; new middleware wiring
  pkg/
    gitutil/
      clone.go                   # Accept credentials; use in git clone
cli/
  main.go                        # --api-key, --wait, --output, --exit-on, --webhook
CLAUDE.md                        # Document deployment modes A/B/C/D
```

---

## Config / mode matrix

Every mode uses the same binary. What differs is env vars. **No new required env vars for dev-local.**

| Env var | Mode A dev | Mode B central | Mode C viewer | Mode D CI (client) |
|---------|-----------|----------------|---------------|--------------------|
| `VULTURE_DB_DSN` | empty (SQLite) or local PG | Neon pooled DSN | Same as B | N/A (CLI) |
| `VULTURE_LOCAL_MODE` | `true` | `false` | `false` | N/A |
| `VULTURE_READONLY` | — | `false` | `true` | N/A |
| `VULTURE_API_KEYS_ENABLED` | `false` (default) | `true` | `true` (optional) | N/A |
| `VULTURE_WEBHOOK_SECRET` | — | random hex | — | N/A |
| `VULTURE_SOURCE_DIR` | `.` | `/var/vulture/sources` | — | — |
| `VULTURE_JWT_SECRET` | auto | long-lived | same as B | — |
| `OPENAI_API_KEY` etc. | user choice | prod key | embedding only | — |

Key property: **`VULTURE_API_KEYS_ENABLED=false` means the API key code paths are loaded but no routes are registered**, so dev-local has zero surface-area exposure to the new feature.

---

## Task 1: API key model + migration

**Files:**
- Create: `backend/internal/model/api_key.go`
- Create: `backend/migrations/011_api_keys.sql`

- [ ] **Step 1: Write failing test**

```go
// backend/internal/model/api_key_test.go
package model

import "testing"

func TestGenerateAPIKey_HasCorrectFormat(t *testing.T) {
	key, hash, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) < 40 {
		t.Fatalf("key too short: %s", key)
	}
	if key[:3] != "vk_" {
		t.Fatalf("expected vk_ prefix: %s", key)
	}
	if len(hash) == 0 {
		t.Fatal("empty hash")
	}
}

func TestVerifyAPIKey_MatchesHash(t *testing.T) {
	key, hash, _ := GenerateAPIKey()
	if !VerifyAPIKey(key, hash) {
		t.Fatal("should verify matching key")
	}
	if VerifyAPIKey("vk_wrong", hash) {
		t.Fatal("should reject wrong key")
	}
}

func TestAPIKeyPrefix_StableForSameKey(t *testing.T) {
	key, _, _ := GenerateAPIKey()
	p1 := APIKeyPrefix(key)
	p2 := APIKeyPrefix(key)
	if p1 != p2 || len(p1) != 10 {
		t.Fatalf("prefix unstable or wrong length: %s %s", p1, p2)
	}
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `cd backend && go test ./internal/model/ -run APIKey -v`
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Implement api_key.go**

```go
// backend/internal/model/api_key.go
package model

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// APIKey is a bearer token for machine-to-machine auth.
type APIKey struct {
	ID         string     // uuid
	Prefix     string     // first 10 chars of key (e.g. "vk_abc123" — safe to display)
	Hash       string     // bcrypt hash of full key
	Name       string     // human label (e.g. "ci-github-actions")
	Scopes     []string   // ["read","write"]; future-proofing
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	CreatedBy  string     // user ID that created it
}

// GenerateAPIKey returns (plaintext, bcrypt hash, error).
// The plaintext is shown ONCE to the creator; only the hash is persisted.
func GenerateAPIKey() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	key := "vk_" + base64.RawURLEncoding.EncodeToString(raw)
	h, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return key, string(h), nil
}

// VerifyAPIKey compares a presented key against a stored bcrypt hash.
func VerifyAPIKey(presented, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(presented)) == nil
}

// APIKeyPrefix extracts the first 10 characters. Used as a lookup index
// (stored unhashed) and for display in the UI without leaking the full key.
func APIKeyPrefix(key string) string {
	if len(key) < 10 {
		return key
	}
	return key[:10]
}
```

- [ ] **Step 4: Run tests, verify pass**

Run: `cd backend && go test ./internal/model/ -run APIKey -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Write migration**

```sql
-- backend/migrations/011_api_keys.sql
CREATE TABLE IF NOT EXISTS api_keys (
    id          TEXT PRIMARY KEY,
    prefix      TEXT NOT NULL,
    hash        TEXT NOT NULL,
    name        TEXT NOT NULL,
    scopes      TEXT NOT NULL DEFAULT '["read","write"]',
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_api_keys_created_by ON api_keys(created_by);
```

Note: SQLite + PostgreSQL both accept this exact SQL (both support `IF NOT EXISTS` on tables/indexes and the `REFERENCES` clause). SQLite foreign keys require `PRAGMA foreign_keys=ON` which Vulture already sets.

- [ ] **Step 6: Commit**

```bash
git add backend/internal/model/api_key.go backend/internal/model/api_key_test.go \
        backend/migrations/011_api_keys.sql
git commit -m "feat(auth): APIKey model + generate/verify helpers + migration"
```

---

## Task 2: API key repository (sqlite + postgres)

**Files:**
- Create: `backend/internal/repository/api_key_repo.go` (interface)
- Create: `backend/internal/repository/sqlite_api_key_repo.go`
- Create: `backend/internal/repository/postgres_api_key_repo.go`
- Create: `backend/internal/repository/mock_api_key_repo.go`

- [ ] **Step 1: Write interface + tests**

```go
// backend/internal/repository/api_key_repo.go
package repository

import "github.com/vulture/backend/internal/model"

type APIKeyRepository interface {
	Create(k *model.APIKey) error
	FindByPrefix(prefix string) (*model.APIKey, error) // returns nil if not found or revoked
	List(createdBy string) ([]model.APIKey, error)
	Revoke(id string) error
	TouchLastUsed(id string) error
}
```

Write a shared test suite (`api_key_repo_shared_test.go`) that runs against both impls using a `setup func() APIKeyRepository` test helper. Must cover:
- Create + FindByPrefix roundtrip
- FindByPrefix returns nil for revoked key
- List returns only non-revoked keys for that creator
- TouchLastUsed updates the column

- [ ] **Step 2: Implement sqlite impl**

Standard pattern (look at `sqlite_repo.go` for example). Key detail: `scopes` column is JSON TEXT; use `json.Marshal/Unmarshal`.

- [ ] **Step 3: Implement postgres impl**

Same interface; use `$1` placeholders; `scopes` is `TEXT` in Postgres too for schema consistency across both DBs.

- [ ] **Step 4: Mock impl**

```go
// backend/internal/repository/mock_api_key_repo.go
package repository

// Used by handler tests; in-memory map.
```

- [ ] **Step 5: Run all repo tests**

Run: `cd backend && go test ./internal/repository/ -run APIKey -v`
Expected: PASS all.

- [ ] **Step 6: Commit**

```bash
git add backend/internal/repository/*api_key*
git commit -m "feat(auth): APIKey repository (sqlite + postgres + mock)"
```

---

## Task 3: API key service

**Files:**
- Create: `backend/internal/service/api_key_service.go`
- Create: `backend/internal/service/api_key_service_test.go`

- [ ] **Step 1: Write failing tests**

```go
// backend/internal/service/api_key_service_test.go (excerpt)
func TestAPIKeyService_CreateReturnsPlaintextOnce(t *testing.T) {
	svc := NewAPIKeyService(&mockAPIKeyRepo{})
	plaintext, stored, err := svc.Create("ci-gha", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if plaintext[:3] != "vk_" {
		t.Fatalf("bad plaintext: %s", plaintext)
	}
	if stored.Hash == plaintext {
		t.Fatal("hash must not equal plaintext")
	}
}

func TestAPIKeyService_VerifyAcceptsValidRejectsInvalid(t *testing.T) {
	repo := &mockAPIKeyRepo{}
	svc := NewAPIKeyService(repo)
	plaintext, _, _ := svc.Create("ci", "u1")
	got, err := svc.Verify(plaintext)
	if err != nil || got == nil {
		t.Fatal("valid key should verify")
	}
	_, err = svc.Verify("vk_bogus")
	if err == nil {
		t.Fatal("bogus key should fail")
	}
}

func TestAPIKeyService_RevokedKeyFailsVerify(t *testing.T) {
	repo := &mockAPIKeyRepo{}
	svc := NewAPIKeyService(repo)
	plaintext, stored, _ := svc.Create("ci", "u1")
	_ = svc.Revoke(stored.ID)
	_, err := svc.Verify(plaintext)
	if err == nil {
		t.Fatal("revoked key should fail")
	}
}
```

- [ ] **Step 2: Implement service**

```go
// backend/internal/service/api_key_service.go
package service

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

type APIKeyService interface {
	Create(name, createdBy string) (plaintext string, stored *model.APIKey, err error)
	Verify(plaintext string) (*model.APIKey, error)
	List(createdBy string) ([]model.APIKey, error)
	Revoke(id string) error
}

type apiKeyService struct {
	repo repository.APIKeyRepository
}

func NewAPIKeyService(r repository.APIKeyRepository) APIKeyService {
	return &apiKeyService{repo: r}
}

func (s *apiKeyService) Create(name, createdBy string) (string, *model.APIKey, error) {
	plaintext, hash, err := model.GenerateAPIKey()
	if err != nil {
		return "", nil, fmt.Errorf("generate: %w", err)
	}
	k := &model.APIKey{
		ID:        uuid.NewString(),
		Prefix:    model.APIKeyPrefix(plaintext),
		Hash:      hash,
		Name:      name,
		Scopes:    []string{"read", "write"},
		CreatedBy: createdBy,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.repo.Create(k); err != nil {
		return "", nil, fmt.Errorf("store: %w", err)
	}
	return plaintext, k, nil
}

func (s *apiKeyService) Verify(plaintext string) (*model.APIKey, error) {
	prefix := model.APIKeyPrefix(plaintext)
	k, err := s.repo.FindByPrefix(prefix)
	if err != nil {
		return nil, err
	}
	if k == nil {
		return nil, fmt.Errorf("not found")
	}
	if !model.VerifyAPIKey(plaintext, k.Hash) {
		return nil, fmt.Errorf("hash mismatch")
	}
	// Fire-and-forget; don't fail verify if this fails
	_ = s.repo.TouchLastUsed(k.ID)
	return k, nil
}

func (s *apiKeyService) List(createdBy string) ([]model.APIKey, error) {
	return s.repo.List(createdBy)
}

func (s *apiKeyService) Revoke(id string) error {
	return s.repo.Revoke(id)
}
```

- [ ] **Step 3: Run tests, verify pass**

- [ ] **Step 4: Commit**

```bash
git add backend/internal/service/api_key_service*.go
git commit -m "feat(auth): APIKeyService with create/verify/list/revoke"
```

---

## Task 4: API key CRUD handlers

**Files:**
- Create: `backend/internal/handler/api_key_handler.go`
- Create: `backend/internal/handler/api_key_handler_test.go`

- [ ] **Step 1: Write failing tests for 3 endpoints**

Tests verify:
- `POST /api/api-keys` with `{"name":"ci"}` returns 200 with `{id, key, prefix, ...}` — plaintext key appears in response **exactly once**.
- `GET /api/api-keys` returns list without `hash` field.
- `DELETE /api/api-keys/:id` sets `revoked_at` and returns 204.
- All three require admin JWT (use `authMW.RequireAdmin`, which exists per codebase conventions).

- [ ] **Step 2: Implement handler**

Reuse existing `writeJSON`, `writeError`. Routes:

```go
// POST /api/api-keys
func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	// Decode {name string}; get user from context; svc.Create; return key once
}

// GET /api/api-keys
func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	// svc.List(userID); return without Hash
}

// DELETE /api/api-keys/:id
func (h *APIKeyHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	// Extract id; svc.Revoke; 204
}
```

Security: the response to `Create` must include the plaintext key. Subsequent reads never return it — only the prefix + metadata. Comment this explicitly in the handler.

- [ ] **Step 3: Wire in `server.go`**

Gated by `cfg.APIKeysEnabled`:

```go
if cfg.APIKeysEnabled {
    apiKeyH := handler.NewAPIKeyHandler(apiKeySvc)
    mux.HandleFunc("/api/api-keys", authMW.RequireAdmin(ReadOnlyGuard(cfg.ReadOnly, apiKeyH.CreateOrList)))
    mux.HandleFunc("/api/api-keys/", authMW.RequireAdmin(ReadOnlyGuard(cfg.ReadOnly, apiKeyH.Revoke)))
}
```

Note: the `ReadOnlyGuard` wrap matters — on a viewer VM (feature 0030), API key writes are rejected too.

- [ ] **Step 4: Commit**

```bash
git add backend/internal/handler/api_key_handler*.go backend/internal/server/server.go
git commit -m "feat(auth): API key CRUD endpoints gated by VULTURE_API_KEYS_ENABLED"
```

---

## Task 5: API key auth middleware path

**Files:**
- Modify: `backend/internal/handler/auth_middleware.go`
- Modify: `backend/internal/handler/auth_middleware_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestAuthMiddleware_AcceptsAPIKey(t *testing.T) {
	mw := &AuthMiddleware{apiKeySvc: fakeAPIKeySvc{validKey: "vk_good"}}
	called := false
	h := mw.Require(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) })
	req := httptest.NewRequest("GET", "/api/audits", nil)
	req.Header.Set("Authorization", "Bearer vk_good")
	rec := httptest.NewRecorder()
	h(rec, req)
	if !called || rec.Code != 200 {
		t.Fatalf("API key should authenticate; code=%d called=%v", rec.Code, called)
	}
}

func TestAuthMiddleware_RejectsInvalidAPIKey(t *testing.T) { ... }
func TestAuthMiddleware_FallsBackToJWTForNonVkPrefix(t *testing.T) { ... }
```

- [ ] **Step 2: Modify Require method**

```go
func (m *AuthMiddleware) Require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m.localMode {
			// existing local-mode passthrough
			next(w, r); return
		}
		token := extractBearer(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "authentication required"); return
		}
		// New: API key path
		if strings.HasPrefix(token, "vk_") && m.apiKeySvc != nil {
			key, err := m.apiKeySvc.Verify(token)
			if err != nil || key == nil {
				writeError(w, http.StatusUnauthorized, "invalid api key"); return
			}
			ctx := context.WithValue(r.Context(), apiKeyCtxKey{}, key.ID)
			ctx = context.WithValue(ctx, userCtxKey{}, &model.User{ID: "apikey:" + key.ID, Role: "apikey"})
			next(w, r.WithContext(ctx)); return
		}
		// Existing JWT path
		user, err := m.verifyJWT(token)
		// ... existing
	}
}
```

Detail: `userCtxKey` already carries the active principal for authorization. For API keys, synthesize a virtual user with role `"apikey"` and ID `apikey:<key-id>` so downstream handlers don't need special cases. Audit log entries can still reference the real api_key_id via `apiKeyCtxKey`.

- [ ] **Step 3: Add `SetAPIKeyService` setter; wire in `server.go`**

- [ ] **Step 4: Run all middleware tests**

Expected: all pass, including existing JWT tests (no regression).

- [ ] **Step 5: Commit**

---

## Task 6: Webhook model + migration + service

**Files:**
- Create: `backend/internal/model/webhook.go`
- Create: `backend/migrations/012_audit_webhooks.sql`
- Create: `backend/internal/repository/webhook_repo.go` (interface + sqlite + postgres)
- Create: `backend/internal/service/webhook_service.go`
- Create: `backend/internal/service/webhook_service_test.go`

- [ ] **Step 1: Model**

```go
// backend/internal/model/webhook.go
package model

import "time"

type WebhookDelivery struct {
	ID         string
	AuditID    string
	URL        string
	Status     string    // "pending","delivered","failed"
	Attempts   int
	LastError  string
	NextRetry  *time.Time
	CreatedAt  time.Time
	DeliveredAt *time.Time
}

type WebhookPayload struct {
	AuditID   string `json:"audit_id"`
	RunID     string `json:"run_id"`
	Status    string `json:"status"`    // "completed","failed"
	Summary   map[string]int `json:"summary"` // {critical:N, high:N, ...}
	FindingsCount int     `json:"findings_count"`
	Scores    map[string]int `json:"scores"`
	CompletedAt time.Time `json:"completed_at"`
}
```

- [ ] **Step 2: Migration**

```sql
-- backend/migrations/012_audit_webhooks.sql
ALTER TABLE audits ADD COLUMN webhook_url TEXT;

CREATE TABLE IF NOT EXISTS audit_webhook_deliveries (
    id            TEXT PRIMARY KEY,
    audit_id      TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    url           TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    attempts      INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT DEFAULT '',
    next_retry    TEXT,
    created_at    TEXT NOT NULL,
    delivered_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_audit ON audit_webhook_deliveries(audit_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_next_retry ON audit_webhook_deliveries(next_retry) WHERE status='pending';
```

Note: the `ALTER TABLE ADD COLUMN` is idempotent on Postgres (>= 13) with `IF NOT EXISTS`, but SQLite lacks that. Use the existing `migrateAddColumns` pattern (swallow errors).

- [ ] **Step 3: Webhook service**

```go
// backend/internal/service/webhook_service.go
package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

type WebhookService interface {
	DeliverAsync(auditID, url string, payload *model.WebhookPayload)
}

type webhookService struct {
	repo   repository.WebhookRepository
	client *http.Client
	secret string // HMAC signing key; from VULTURE_WEBHOOK_SECRET
}

func NewWebhookService(r repository.WebhookRepository) WebhookService {
	return &webhookService{
		repo:   r,
		client: &http.Client{Timeout: 10 * time.Second},
		secret: os.Getenv("VULTURE_WEBHOOK_SECRET"),
	}
}

func (s *webhookService) DeliverAsync(auditID, url string, payload *model.WebhookPayload) {
	if url == "" {
		return
	}
	go s.deliver(auditID, url, payload)
}

func (s *webhookService) deliver(auditID, url string, payload *model.WebhookPayload) {
	body, _ := json.Marshal(payload)
	sig := s.sign(body)
	backoff := []time.Duration{0, 2 * time.Second, 10 * time.Second}
	for attempt, d := range backoff {
		if d > 0 { time.Sleep(d) }
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Vulture-Signature", sig)
		req.Header.Set("X-Vulture-Delivery", auditID)
		resp, err := s.client.Do(req)
		cancel()
		if err == nil && resp.StatusCode < 400 {
			_, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close()
			s.recordSuccess(auditID, url, attempt+1)
			return
		}
		if resp != nil { resp.Body.Close() }
		s.recordAttempt(auditID, url, attempt+1, fmt.Sprintf("%v status=%v", err, resp))
	}
}

func (s *webhookService) sign(body []byte) string {
	if s.secret == "" { return "" }
	m := hmac.New(sha256.New, []byte(s.secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// recordSuccess / recordAttempt persist to audit_webhook_deliveries.
```

- [ ] **Step 4: Tests with httptest**

Write a local HTTP server; submit delivery; assert header + signature; assert retry on 500.

- [ ] **Step 5: Wire into audit completion**

In `backend/internal/handler/stream_handler.go:persistResults`, after `completeAudit` succeeds, fetch the audit's `webhook_url` and call `webhookSvc.DeliverAsync(...)`.

- [ ] **Step 6: Commit**

---

## Task 7: Per-source git credentials

**Files:**
- Modify: `backend/internal/model/source.go` — add `GitCredentials *GitCredentials` (optional)
- Modify: `backend/internal/service/source_service.go`
- Modify: `backend/pkg/gitutil/clone.go` — accept optional token
- Modify: `backend/internal/handler/source_handler.go` — accept `git_credentials` in request body

- [ ] **Step 1: Add model**

```go
// backend/internal/model/source.go (addition)
type GitCredentials struct {
	Type  string // "token" | "ssh_key"
	Value string // token string or PEM
}
```

- [ ] **Step 2: Modify gitutil.Clone**

```go
// backend/pkg/gitutil/clone.go
func Clone(url, ref, destDir string, creds *model.GitCredentials) error {
	env := os.Environ()
	args := []string{"clone", "--depth", "1", "--branch", ref}
	if creds != nil && creds.Type == "token" {
		// Rewrite HTTPS URL to embed token once: https://x-access-token:TOKEN@host/...
		url = rewriteTokenURL(url, creds.Value)
	}
	if creds != nil && creds.Type == "ssh_key" {
		tmpKey, _ := os.CreateTemp("", "vulture-ssh-*")
		tmpKey.WriteString(creds.Value); tmpKey.Close()
		defer os.Remove(tmpKey.Name())
		env = append(env, "GIT_SSH_COMMAND=ssh -i "+tmpKey.Name()+" -o StrictHostKeyChecking=no")
	}
	args = append(args, url, destDir)
	cmd := exec.Command("git", args...)
	cmd.Env = env
	return cmd.Run()
}
```

Key rules:
- Credentials are **never logged** (redacted in error messages).
- Credentials are **never persisted** (used once, discarded).
- SSH key files written to `os.TempDir()` with `0600` perms, deleted immediately after clone.

- [ ] **Step 3: Handler accepts credentials in POST body**

```go
// POST /api/sources body
type SourceRequest struct {
    Type string `json:"type"`
    Path string `json:"path,omitempty"`
    URL  string `json:"url,omitempty"`
    Ref  string `json:"ref,omitempty"`
    GitCredentials *model.GitCredentials `json:"git_credentials,omitempty"`
}
```

Validation: credentials only valid if `type=="git"`.

- [ ] **Step 4: Tests**

- Credentials forwarded to Clone
- Credentials not logged (grep the log writer)
- Credentials not stored (check source row in DB has no credentials field)

- [ ] **Step 5: Commit**

---

## Task 8: Per-run source directory isolation

**Files:**
- Modify: `backend/internal/service/source_service.go`
- Modify: `backend/internal/service/audit_service.go` (cleanup on completion)

Currently `/tmp/sources/<source-id>/` — if two audits clone the same repo concurrently, they collide.

- [ ] **Step 1: Failing test**

Concurrent `ingestGit` with same URL + different refs; verify separate directories.

- [ ] **Step 2: Modify path**

```go
// Before:
destDir := filepath.Join("/tmp/sources", src.ID)
// After:
destDir := filepath.Join("/tmp/sources", src.ID, "run-"+runID)
// where runID is a new field in SourceRequest (or generated)
```

The `audits` table gains no new column — just pass through. Source identity in DB still keyed by URL+ref, but physical disk location is unique per audit run.

- [ ] **Step 3: Cleanup on audit complete**

In `persistResults`, after all processing: `os.RemoveAll(auditSourceDir)`. Guard with a configurable retention TTL (`VULTURE_SOURCE_RETENTION_MIN`, default 0 = immediate).

- [ ] **Step 4: Commit**

---

## Task 9: Rate-limit middleware per API key

**Files:**
- Modify: `backend/internal/server/middleware.go`

- [ ] **Step 1: Add `RateLimitByKey` that keys on `apiKeyCtxKey` in request context, falling back to IP**

- [ ] **Step 2: Wire in server.go for write endpoints**

Defaults: 60 req/min per key, 10 concurrent in-flight audits per key. Configurable via `VULTURE_APIKEY_RPM`, `VULTURE_APIKEY_MAX_CONCURRENT`.

- [ ] **Step 3: Tests**

---

## Task 10: CLI — --api-key, --wait, --output, --exit-on, --webhook

**Files:**
- Modify: `cli/main.go`

- [ ] **Step 1: Add flags**

```go
// New flags
apiKey    := flag.String("api-key", "", "API key for server authentication")
server    := flag.String("server", "", "Server URL (overrides config.ini)")
wait      := flag.Bool("wait", false, "Block until audit completes")
output    := flag.String("output", "text", "Output format: text|json")
exitOn    := flag.String("exit-on", "", "Exit non-zero if findings of this severity or higher: critical|high|medium|low")
webhook   := flag.String("webhook", "", "POST completion notification to this URL")
ref       := flag.String("ref", "", "Git ref (branch/tag/SHA) when --url is a git URL")
```

- [ ] **Step 2: Auth selection logic**

```go
if *apiKey != "" {
    token = *apiKey        // use as bearer directly
} else if token == "" {
    token = readStoredToken() // existing behavior
}
```

- [ ] **Step 3: Polling loop with exit code**

```go
if *wait {
    for {
        aud := apiGet[Audit](serverURL+"/api/audits/"+auditID, token)
        if aud.Status == "completed" || aud.Status == "failed" { break }
        time.Sleep(5 * time.Second)
    }
    if *output == "json" {
        json.NewEncoder(os.Stdout).Encode(aud)
    } else {
        printAuditSummary(aud)
    }
    if exitCode := computeExitCode(aud, *exitOn); exitCode != 0 {
        os.Exit(exitCode)
    }
}
```

- [ ] **Step 4: Tests**

Mock backend via `httptest`; verify --wait polls; verify --exit-on returns expected code.

- [ ] **Step 5: Commit**

---

## Task 11: CLI `api-key` subcommand

**Files:**
- Create: `cli/apikey.go`
- Modify: `cli/main.go` — dispatch subcommand

- [ ] **Step 1: Subcommands**

```
vulture api-key create <name>         # creates, prints plaintext once
vulture api-key list                   # list prefixes, names, last_used_at
vulture api-key revoke <id>            # revokes
```

All require the admin user to be logged in (existing `vulture login` flow).

- [ ] **Step 2: Implementation**

Standard REST calls to `/api/api-keys`. Output the plaintext key **once** with a very clear "save this now — you will not see it again" message.

- [ ] **Step 3: Tests**

- [ ] **Step 4: Commit**

---

## Task 12: CI workflow templates

**Files:**
- Create: `.github/workflow-examples/vulture-audit.yml`
- Create: `docs/guides/ci_integration.md`

- [ ] **Step 1: GitHub Actions template**

```yaml
# .github/workflow-examples/vulture-audit.yml
name: Vulture Audit

on:
  pull_request:
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Submit audit
        env:
          VULTURE_SERVER: ${{ secrets.VULTURE_SERVER_URL }}
          VULTURE_API_KEY: ${{ secrets.VULTURE_API_KEY }}
          GITHUB_DEPLOY_KEY: ${{ secrets.VULTURE_REPO_DEPLOY_KEY }}
        run: |
          curl -fsSL $VULTURE_SERVER/releases/latest/vulture-linux-amd64 -o /usr/local/bin/vulture
          chmod +x /usr/local/bin/vulture
          vulture scan ${{ github.server_url }}/${{ github.repository }}.git \
            --ref ${{ github.sha }} \
            --server $VULTURE_SERVER \
            --api-key $VULTURE_API_KEY \
            --git-credentials "token:$GITHUB_TOKEN" \
            --types cwe,owasp,do178c \
            --wait --exit-on high --output json > audit-report.json
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with: { name: vulture-audit, path: audit-report.json }
```

- [ ] **Step 2: GitLab + Jenkins examples in docs/guides/ci_integration.md**

Follow same pattern; adapt to platform.

- [ ] **Step 3: Commit**

---

## Task 13: Central server deployment guide

**Files:**
- Create: `docs/guides/central_server_deployment.md`

Content:

1. **Prerequisites:** VM (2 vCPU, 4 GB RAM minimum), Docker, Neon account, domain + TLS cert.
2. **Step 1: provision Neon** (reference `docs/guides/neon_deployment.md`).
3. **Step 2: provision VM**, install Docker, clone vulture.
4. **Step 3: configure `.env`** — `VULTURE_API_KEYS_ENABLED=true`, `VULTURE_WEBHOOK_SECRET=$(openssl rand -hex 32)`, DSN to Neon.
5. **Step 4: `docker compose up -d --build`** — same compose as dev-local.
6. **Step 5: reverse proxy** — Caddy one-liner for TLS termination:
   ```
   vulture.example.com {
     reverse_proxy localhost:28080
   }
   ```
7. **Step 6: bootstrap admin**
   ```bash
   # First user via CLI:
   vulture login --register --email admin@example.com
   # Create first API key:
   vulture api-key create ci-github-actions
   ```
8. **Step 7: configure CI** — reference `ci_integration.md`.
9. **Operations:** logs (`docker compose logs -f backend`), monitoring endpoints, backup strategy (Neon PITR).

---

## Task 14: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] Replace the existing "Deployment Topologies" section with a four-mode matrix:

```markdown
### Deployment Modes

Same binaries and Docker images serve all modes. Mode selection is via env vars only.

| Mode | Who runs it | Command | Notes |
|------|-------------|---------|-------|
| A: Dev-local | Developer laptop | `docker compose up` | SQLite or local Postgres; LOCAL_MODE=true |
| B: Centralized server | Ops VM | `docker compose up -d` + Neon DSN + `VULTURE_API_KEYS_ENABLED=true` | See `docs/guides/central_server_deployment.md` |
| C: Read-only viewer VM | Ops VM | `docker compose -f docker-compose.readonly.yml up -d` | Optional; see feature 0030 |
| D: CI client | GitHub Actions etc. | `vulture scan <git-url> --api-key X --server Y --wait` | See `docs/guides/ci_integration.md` |

Key property: Mode A is the default when you clone the repo. No new env vars are required; all centralized features are opt-in.
```

- [ ] Commit.

---

## Task 15: E2E test — simulated CI workflow

**Files:**
- Create: `backend/test/e2e/ci_workflow_test.go`

- [ ] **Step 1: Test spec**

```go
// +build e2e
func TestCIWorkflow_EndToEnd(t *testing.T) {
    // 1. Spin backend + mock agent via docker-compose.test.yml
    // 2. Create admin user; login; create API key
    // 3. POST /api/audits with git URL + webhook URL (local httptest)
    // 4. Poll /api/audits/:id until status=completed
    // 5. Assert: findings persisted in DB
    // 6. Assert: webhook was delivered with HMAC signature verified
    // 7. Assert: audit row has api_key_id set
    // 8. Cleanup
}
```

- [ ] **Step 2: Wire into `make e2e`**

- [ ] **Step 3: Commit**

---

## Backwards compatibility acceptance criteria

Before merging, all must be true:

- [ ] `docker compose up` on a fresh checkout works with **no env vars set** — identical UX to today.
- [ ] All existing backend tests pass (~180 tests).
- [ ] All existing frontend tests pass (~300 tests).
- [ ] Existing SQLite DBs get migrated automatically at startup (new tables created; no data touched).
- [ ] Existing Postgres DBs get migrated via migrations 011-012 (idempotent).
- [ ] Existing JWT-authenticated users continue to log in and use the UI without change.
- [ ] `/api/agents`, `/api/audits`, all existing endpoints behave identically when API keys are disabled.
- [ ] No new **required** env vars; all new features gated behind flags.

---

## Self-review checklist

- [ ] Single-host dev mode (Mode A) unchanged — no forced env vars, no required external services
- [ ] API keys opt-in via `VULTURE_API_KEYS_ENABLED`
- [ ] Webhooks opt-in per-request (`webhook_url` in audit POST body)
- [ ] Git credentials handled per-request, never persisted, never logged
- [ ] Per-run source directories prevent concurrent-scan collisions
- [ ] CLI new flags don't break existing invocations
- [ ] Migrations 011 + 012 are idempotent on both SQLite and Postgres
- [ ] Rate limits don't apply to Mode A (since API keys disabled there)
- [ ] Documentation covers all 4 modes and migration path between them

---

## Out of scope (explicitly)

These are legitimate future items but not part of this feature:

- **Horizontal scaling** — single VM; if you need 100+ scans/day, add a queue and multiple workers (future feature)
- **Source-upload (tarball) mode** — git URL covers 95% of CI cases; defer
- **Live SSE streaming from CI to the central UI** — CI polls; UI users hitting server directly still see live
- **Fine-grained API key scopes** — all keys grant read+write today; role-based scoping is a future feature
- **Multi-tenancy** — single Neon, no row-level isolation; adequate for single-org deployments
- **Webhook delivery UI** — only the log table; management UI later
- **Credential vault integration** (Vault, AWS Secrets Manager) — use env vars for now

---

## Rollback

Every task is committed separately. Rollback is per-task `git revert`. Because every feature is opt-in:

- Reverting API keys: existing JWT auth still works, everyone unaffected
- Reverting webhooks: audits complete normally; just no callback
- Reverting credentials: existing public-repo clones still work
- Reverting per-run dirs: concurrent same-repo audits collide (regression risk — revert last)
- Reverting CLI flags: existing CLI invocations unaffected

Full rollback via `git revert <task15>..<task1>`. No data migration needed — migrations 011-012 are additive and safe to leave in place even after code revert.

See `0031_rollback_plan.md` for detail.

---

## Estimated effort

| Task | Hours |
|------|-------|
| 1. API key model + migration | 1 |
| 2. Repositories (sqlite + postgres) | 2 |
| 3. API key service | 1 |
| 4. API key handlers | 2 |
| 5. Auth middleware API-key path | 2 |
| 6. Webhook service + dispatch | 3 |
| 7. Per-source git credentials | 2 |
| 8. Per-run source dirs | 1 |
| 9. Rate limit by key | 1 |
| 10. CLI flags (--api-key, --wait, etc.) | 2 |
| 11. CLI `api-key` subcommand | 1 |
| 12. CI templates + docs | 2 |
| 13. Central server deployment guide | 1 |
| 14. CLAUDE.md update | 0.25 |
| 15. E2E test | 2 |
| **Total** | **~23 hours (~3 working days)** |

Realistic calendar time with review + iteration: **1 sprint (5 working days)**.
