# Authentication System - Rollback Plan

## Risk Assessment
- **Severity**: Medium - Auth protects all API endpoints
- **Blast radius**: All API calls, SSE streams, frontend routing
- **Data loss risk**: None - user data in PostgreSQL persists independently

## Rollback Steps

### 1. Disable Auth Middleware
In `server.go`, replace `auth.Require(handler)` with direct handler:
```go
// Before: mux.HandleFunc("/api/audits", auth.Require(auditHandler.Create))
// After:  mux.HandleFunc("/api/audits", auditHandler.Create)
```

### 2. Disable Frontend Auth Guards
In `App.tsx`, remove the auth check wrapper around protected routes. Render all routes directly.

### 3. Remove Login/Register Pages (if needed)
In `App.tsx`, remove `/login` and `/register` routes. In `Sidebar.tsx`, remove user profile section.

### 4. Database Cleanup (if needed)
```sql
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS teams;
```

## Verification
1. All API endpoints should be accessible without tokens
2. Frontend should load directly to Dashboard without login
3. SSE streams should connect without `?token=` parameter
4. Existing audits and memories remain unaffected

## Recovery Time
- Disable middleware: 5 minutes (comment out middleware wrapping)
- Full rollback: 15 minutes (remove routes + DB tables)
