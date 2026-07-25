# 0028 - SSE Stream Tokens

## Problem

The frontend passes the long-lived JWT (24h TTL) as a `?token=` query parameter when
opening SSE `EventSource` connections. The browser `EventSource` API cannot set custom
headers, so the JWT cannot be sent via `Authorization: Bearer`. This exposes the
credential in server access logs, browser history, HTTP Referrer headers, and network
monitoring tools.

## Solution

Replace the long-lived JWT in SSE URLs with a short-lived, single-use **stream token**.

1. Frontend calls `POST /api/audits/:id/stream-token` (authenticated via JWT header).
2. Backend generates a cryptographically random 32-byte token, stores it in an in-memory
   map with a 60-second TTL, scoped to the audit ID and user ID.
3. Backend returns `{"stream_token": "..."}`.
4. Frontend opens `EventSource` with `?stream_token=<token>` instead of `?token=<jwt>`.
5. Backend auth middleware validates the stream token on `/stream` paths: checks expiry,
   marks it as used (single-use), injects the user into the request context.

## Architecture

```
Frontend                          Backend
   |                                 |
   |-- POST /audits/:id/stream-token (JWT in Authorization header)
   |                                 |-- generate 32-byte random token
   |                                 |-- store in sync.Map {hash -> StreamToken}
   |                                 |-- return {"stream_token": "..."}
   |<--------------------------------|
   |                                 |
   |-- GET /audits/:id/stream?stream_token=<token>
   |                                 |-- look up token in sync.Map
   |                                 |-- validate: not expired, not used, audit ID matches
   |                                 |-- mark used, inject user into context
   |                                 |-- proceed to SSE stream handler
   |<======== SSE events ==========>|
```

## Implementation Tasks

### Task 1: Backend - Stream token store (`internal/service/stream_token.go`)

New file. In-memory token store using `sync.Map`.

```go
type StreamToken struct {
    TokenHash string
    AuditID   string
    UserID    string
    ExpiresAt time.Time
    Used      bool
}

type StreamTokenStore struct { /* sync.Map + cleanup */ }
func (s *StreamTokenStore) Create(auditID, userID string) (rawToken string, err error)
func (s *StreamTokenStore) Validate(rawToken, auditID string) (*model.User, error)
func (s *StreamTokenStore) cleanup()  // goroutine, runs every 60s
```

- Token generation: `crypto/rand` 32 bytes, base64url-encoded
- Storage key: SHA-256 hash of raw token (never store raw token)
- TTL: 60 seconds
- Single-use: `Used` flag set on first validation
- Lazy cleanup goroutine removes expired tokens every 60 seconds

### Task 2: Backend - Stream token endpoint (`internal/handler/stream_handler.go`)

Add method to `StreamHandler`:

```go
func (h *StreamHandler) CreateStreamToken(w http.ResponseWriter, r *http.Request)
```

- Extracts audit ID from URL path
- Gets user from request context (requires auth)
- Calls `StreamTokenStore.Create(auditID, userID)`
- Returns `{"stream_token": "..."}`

### Task 3: Backend - Auth middleware extension (`internal/handler/auth_middleware.go`)

Extend `extractUser()` to check `stream_token` query parameter:

```go
if streamToken := r.URL.Query().Get("stream_token"); streamToken != "" {
    // Only accept on /stream paths
    if strings.HasSuffix(r.URL.Path, "/stream") {
        return m.streamTokenStore.Validate(streamToken, auditID)
    }
}
```

- Stream tokens are ONLY accepted on paths ending with `/stream`
- The audit ID is extracted from the URL path for scope validation
- Stream tokens are checked BEFORE the JWT fallback (if stream_token param is present,
  don't fall through to JWT query param check)

### Task 4: Backend - Route registration (`internal/server/server.go`)

- Wire `StreamTokenStore` into `AuthMiddleware` and `StreamHandler`
- Register `POST /api/audits/:id/stream-token` with `protect()` wrapper
- Start the cleanup goroutine

### Task 5: Frontend - API client (`src/lib/api.ts`)

Replace:
```typescript
getStreamUrl(auditId: string): string {
    const token = localStorage.getItem("vulture_token");
    const base = `${API_BASE}/api/audits/${auditId}/stream`;
    return token ? `${base}?token=${encodeURIComponent(token)}` : base;
}
```

With:
```typescript
async getStreamToken(auditId: string): Promise<string> {
    const resp = await request<{ stream_token: string }>(
        `/api/audits/${auditId}/stream-token`,
        { method: "POST" }
    );
    return resp.stream_token;
}

getStreamUrl(auditId: string, streamToken: string): string {
    const base = `${API_BASE}/api/audits/${auditId}/stream`;
    return `${base}?stream_token=${encodeURIComponent(streamToken)}`;
}
```

### Task 6: Frontend - SSE hook (`src/hooks/useAgentStream.ts`)

Update the `useEffect` that opens the EventSource:

```typescript
// Before opening EventSource, fetch a stream token
const streamToken = await api.getStreamToken(auditId);
const url = api.getStreamUrl(auditId, streamToken);
const es = new EventSource(url);
```

Handle token fetch failure gracefully (set error state, don't open EventSource).

## Rollback Plan

1. Revert the frontend changes (restore `getStreamUrl` to use `?token=` with JWT)
2. Revert `auth_middleware.go` stream_token check (JWT query param fallback still works)
3. Remove `stream_token.go` and route registration
4. The old JWT-in-query-param path still works as-is — no data migration needed

## Testing

- Unit test: `StreamTokenStore` create/validate/expiry/single-use/audit-scope
- Unit test: `CreateStreamToken` handler returns valid token
- Unit test: `extractUser` accepts stream_token on /stream paths, rejects on other paths
- E2E test: full flow — create audit, get stream token, open SSE, receive events
