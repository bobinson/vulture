# Authentication System - Implementation Plan

## Overview
JWT-based authentication with bcrypt password hashing, team management, and role-based access control. Supports both Bearer token headers and query parameter tokens (for SSE EventSource connections).

## Architecture

### Authentication Flow
```
Register/Login → bcrypt verify → HMAC-SHA256 JWT → Bearer token
                                                  → localStorage (frontend)
                                                  → Authorization header (API)
                                                  → ?token= query param (SSE)
```

### Storage Layer
- **PostgreSQL**: `users` table with UUID primary key, bcrypt password hash
- **Teams**: `teams` table linked via `team_id` foreign key on users
- **Password**: bcrypt with default cost (10 rounds)

### Token Format
- **Algorithm**: HMAC-SHA256 (HS256)
- **Expiry**: 24 hours from issuance
- **Claims**: `sub` (user_id), `email`, `role`, `team_id`, `iat`, `exp`
- **Secret**: Configurable via `VULTURE_JWT_SECRET` environment variable

### Security Measures
- Password hash never serialized to JSON (`json:"-"` tag)
- Minimum 8-character password requirement
- Token signature verification before claim parsing
- Expiry check on every request
- Duplicate email prevention at registration

## API Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/auth/register` | None | Create account + optional team |
| POST | `/api/auth/login` | None | Authenticate, receive JWT |
| GET | `/api/auth/me` | Required | Get current user profile |

## Components

### Backend (Go)
- `model/user.go` - User, Team, LoginRequest, RegisterRequest, AuthResponse structs
- `repository/user_repo.go` - PostgreSQL CRUD for users and teams
- `service/auth_service.go` - Register, Login, ValidateToken, JWT generation
- `handler/auth_handler.go` - HTTP handlers for auth endpoints
- `handler/auth_middleware.go` - Require/Optional middleware, token extraction

### Frontend (React)
- `lib/auth.tsx` - AuthProvider context, useAuth hook
- `pages/Login.tsx` - Email/password login form
- `pages/Register.tsx` - Registration with optional team name
- `App.tsx` - Route guards (authenticated vs public routes)

## Middleware

### AuthMiddleware.Require
Blocks unauthenticated requests (401). Used on audit, source, memory endpoints.

### AuthMiddleware.Optional
Passes through without user context. Used on health and public endpoints.

### Token Extraction Priority
1. `Authorization: Bearer <token>` header
2. `?token=<token>` query parameter (SSE fallback)

## Data Model

```sql
CREATE TABLE teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    team_id UUID REFERENCES teams(id),
    created_at TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ
);
```

## Dependencies
- `golang.org/x/crypto/bcrypt` for password hashing
- `crypto/hmac` + `crypto/sha256` for JWT signing (stdlib)
- `encoding/base64` for JWT encoding (stdlib)
- React Context API for frontend auth state

## Testing
- Go: Unit tests for auth_service (register, login, token validation, expiry)
- Go: Unit tests for auth_middleware (require, optional, token extraction)
- Go: Unit tests for auth_handler (register validation, login flow, me endpoint)
- Frontend: Vitest tests for Login page (10 tests)
- Frontend: Vitest tests for Register page (11 tests)
- Frontend: Auth context integration tests
