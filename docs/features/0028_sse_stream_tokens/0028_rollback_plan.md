# 0028 - SSE Stream Tokens - Rollback Plan

## Rollback Steps

1. Revert `frontend/src/lib/api.ts` — restore `getStreamUrl()` to use `?token=` with JWT
2. Revert `frontend/src/hooks/useAgentStream.ts` — remove async stream token fetch
3. Revert `backend/internal/handler/auth_middleware.go` — remove stream_token check
4. Remove `backend/internal/service/stream_token.go`
5. Revert route registration in `backend/internal/server/server.go`

## Risk Assessment

- **Data loss**: None. Stream tokens are ephemeral (in-memory, 60s TTL).
- **Breaking change**: None. The old JWT query param path is the fallback.
- **Downtime**: Zero. Rolling back is a code-only change.
