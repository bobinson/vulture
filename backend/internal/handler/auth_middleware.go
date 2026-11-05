package handler

import (
	"context"
	"net/http"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

type contextKey string

const userContextKey contextKey = "user"

// tokenAuthKey marks a request whose principal came from a presented
// credential (a stream token, a Bearer token or API key, or the session
// cookie), not from local mode's implicit local admin (0074 item 1b: a
// masked value is never shown to a request that presented nothing).
const tokenAuthKey contextKey = "token_auth"

// credKindKey holds the credKind the request presented, so a route can refuse
// a kind (RequireBearerCredential).
const credKindKey contextKey = "cred_kind"

type AuthMiddleware struct {
	authSvc          service.AuthService
	streamTokenStore *service.StreamTokenStore
	localUser        *model.User
	apiKeySvc        service.APIKeyService // optional; nil when API keys disabled
}

func NewAuthMiddleware(authSvc service.AuthService) *AuthMiddleware {
	return &AuthMiddleware{authSvc: authSvc}
}

// SetAPIKeyService enables API-key bearer-token auth. Safe to call with nil.
func (m *AuthMiddleware) SetAPIKeyService(svc service.APIKeyService) {
	m.apiKeySvc = svc
}

// SetLocalMode enables local mode by resolving and caching the local admin user.
func (m *AuthMiddleware) SetLocalMode(enabled bool) {
	if !enabled {
		m.localUser = nil
		return
	}
	user, err := m.authSvc.ValidateLocalUser()
	if err != nil {
		m.localUser = nil
		return
	}
	m.localUser = user
}

// Require admits a request whose credential resolves to a principal, or, in
// local mode, any request that the CSRF rule does not refuse (as the implicit
// local admin). Everything else is answered 401 or 403 here.
func (m *AuthMiddleware) Require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authed, ok := m.authenticate(w, r); ok {
			next(w, authed)
		}
	}
}

// authenticate resolves the request's principal and returns the request
// carrying it, its credential kind and whether a credential produced it.
// When it returns false it has written the 403 (CSRF) or 401 answer.
func (m *AuthMiddleware) authenticate(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	user, kind, ok := m.identify(r)
	if !ok {
		writeCSRFRequired(w)
		return nil, false
	}
	presented := user != nil
	if !presented {
		user = m.localUser
	}
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	ctx := context.WithValue(r.Context(), tokenAuthKey, presented)
	ctx = context.WithValue(ctx, credKindKey, kind)
	return r.WithContext(context.WithValue(ctx, userContextKey, user)), true
}

func (m *AuthMiddleware) Optional(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if user, _, _ := m.identify(r); user != nil {
			ctx := context.WithValue(r.Context(), userContextKey, user)
			r = r.WithContext(ctx)
		}
		next(w, r)
	}
}

// SetStreamTokenStore sets the stream token store for validating ephemeral SSE tokens.
func (m *AuthMiddleware) SetStreamTokenStore(store *service.StreamTokenStore) {
	m.streamTokenStore = store
}

// credKind is the kind of credential a request presented.
type credKind uint8

const (
	credNone   credKind = iota
	credStream          // the stream_token query parameter
	credBearer          // an Authorization header (a JWT or an API key)
	credCookie          // the session cookie (a JWT)
)

// credential returns the request's one credential and its kind, in
// precedence order: a stream_token, then an Authorization header, then the
// session cookie. A credential that is present decides alone, even when it
// does not validate: it never falls through to the next one. Any
// Authorization header counts, so one that is not "Bearer" gives an empty
// token. A Bearer request costs no allocation.
func (m *AuthMiddleware) credential(r *http.Request) (string, credKind) {
	if t := streamTokenParam(r); t != "" {
		return t, credStream
	}
	if h := r.Header.Get("Authorization"); h != "" {
		return bearerToken(h), credBearer
	}
	if t := sessionCookieToken(r); t != "" {
		return t, credCookie
	}
	return "", credNone
}

// streamTokenParam returns the stream_token query parameter. The query is
// parsed only when its raw form may hold that key, literally or
// percent-encoded, so most requests skip the parse and an encoded key still
// reaches it.
func streamTokenParam(r *http.Request) string {
	q := r.URL.RawQuery
	if !strings.Contains(q, "stream_token") && !strings.Contains(q, "%") {
		return ""
	}
	return r.URL.Query().Get("stream_token")
}

// bearerToken is the token of a "Bearer <token>" header, or "" for any other
// scheme.
func bearerToken(h string) string {
	t, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return ""
	}
	return t
}

// identify resolves the request's credential: the principal it validates to
// (nil when there is none or it does not validate) and its kind. ok is false
// when the CSRF rule refuses the request, which is decided before any lookup.
func (m *AuthMiddleware) identify(r *http.Request) (*model.User, credKind, bool) {
	token, kind := m.credential(r)
	if csrfRefused(kind, r) {
		return nil, kind, false
	}
	return m.resolveCredential(r, token, kind), kind, true
}

// resolveCredential is the principal token validates to as a credential of
// kind, or nil. The session cookie holds a JWT only, so an API key carried in
// it validates to nothing.
func (m *AuthMiddleware) resolveCredential(r *http.Request, token string, kind credKind) *model.User {
	switch kind {
	case credStream:
		return m.streamUser(r, token)
	case credBearer:
		return m.bearerUser(token)
	case credCookie:
		return m.jwtUser(token)
	}
	return nil
}

// streamUser validates a short-lived stream token. It is honoured only on
// /api/audits/{id}/stream, and only for the audit that path names.
func (m *AuthMiddleware) streamUser(r *http.Request, token string) *model.User {
	if m.streamTokenStore == nil || !isAuditStreamPath(r.URL.Path) {
		return nil
	}
	user, err := m.streamTokenStore.Validate(token, extractAuditIDFromPath(r.URL.Path))
	if err != nil {
		return nil
	}
	return user
}

// bearerUser validates a Bearer token. The "vk_" prefix marks an API key; a
// failed API-key check never falls through to the JWT check, since the two
// schemes are not interchangeable.
func (m *AuthMiddleware) bearerUser(token string) *model.User {
	if strings.HasPrefix(token, "vk_") {
		return m.apiKeyUser(token)
	}
	return m.jwtUser(token)
}

// apiKeyUser is the synthetic "apikey" principal of a valid API key, or nil
// (also when API keys are disabled).
func (m *AuthMiddleware) apiKeyUser(token string) *model.User {
	if m.apiKeySvc == nil {
		return nil
	}
	key, err := m.apiKeySvc.Verify(token)
	if err != nil || key == nil {
		return nil
	}
	return &model.User{ID: "apikey:" + key.ID, Role: "apikey"}
}

// jwtUser is the user a valid JWT names, or nil.
func (m *AuthMiddleware) jwtUser(token string) *model.User {
	user, err := m.authSvc.ValidateToken(token)
	if err != nil {
		return nil
	}
	return user
}

// csrfRefused reports whether the CSRF rule refuses the request: an unsafe
// method authenticated by the session cookie must carry CSRFHeader. Browsers
// attach the cookie by themselves; a Bearer token, API key or stream token
// they never do, so those requests are not affected.
func csrfRefused(kind credKind, r *http.Request) bool {
	return kind == credCookie && !IsSafeMethod(r.Method) && !hasCSRFHeader(r)
}

// isAuditStreamPath returns true only for /api/audits/{id}/stream (not other /stream suffixes)
func isAuditStreamPath(path string) bool {
	trimmed := strings.TrimPrefix(path, "/api/audits/")
	if trimmed == path {
		return false // didn't start with /api/audits/
	}
	// Must be exactly "{id}/stream" — one segment then /stream
	parts := strings.SplitN(trimmed, "/", 2)
	return len(parts) == 2 && parts[0] != "" && parts[1] == "stream"
}

// extractAuditIDFromPath extracts the audit ID from paths like /api/audits/{id}/stream
func extractAuditIDFromPath(path string) string {
	path = strings.TrimPrefix(path, "/api/audits/")
	if idx := strings.Index(path, "/"); idx > 0 {
		return path[:idx]
	}
	return path
}

// isWriteRole reports whether a principal role may perform state-changing
// requests: a human writer (member, admin) or "apikey". "apikey" is included
// deliberately: API-key principals are minted with that synthetic role (see
// Require), keys can only be created by an admin, and they are the documented
// Mode-D / CI write credential (`vulture scan --api-key ...`). Excluding it
// 403s every CI client.
func isWriteRole(role string) bool { return humanWriter(role) || role == "apikey" }

// IsSafeMethod reports whether m is a read-only HTTP method: GET, HEAD or
// OPTIONS, matched exactly as net/http spells them.
func IsSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// requireRoleWhere is the one role gate the Require* wrappers share: it
// answers 403 with msg unless the request's principal has a role that
// allowed admits. Must be applied inside authMW.Require so
// getUserFromContext sees the DB-fresh principal.
func requireRoleWhere(allowed func(string) bool, msg string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if u := getUserFromContext(r); u == nil || !allowed(u.Role) {
			writeError(w, http.StatusForbidden, msg)
			return
		}
		next(w, r)
	}
}

// RequireWrite gates only state-changing methods so combined GET+POST handlers
// (e.g. /api/audits) keep serving reads to viewers (0065 §H1). Safe methods
// pass straight through; writes require a role isWriteRole admits. Must be
// applied inside authMW.Require.
func RequireWrite(next http.HandlerFunc) http.HandlerFunc {
	gated := requireRoleWhere(isWriteRole, "write access requires member, admin, or api-key credentials", next)
	return func(w http.ResponseWriter, r *http.Request) {
		if IsSafeMethod(r.Method) {
			next(w, r)
			return
		}
		gated(w, r)
	}
}

// RequireRole gates an entire handler to a specific role (for /api/admin/*).
// Must be applied inside authMW.Require. 0065 §H7.
func RequireRole(role string, next http.HandlerFunc) http.HandlerFunc {
	return requireRoleWhere(func(r string) bool { return r == role }, "requires "+role+" role", next)
}

// RequireHumanWriter admits only human writers (member or admin), on EVERY
// method, to a route that viewers and API keys have no use for, such as
// folder browse (0102). Must be applied inside authMW.Require.
func RequireHumanWriter(next http.HandlerFunc) http.HandlerFunc {
	return requireRoleWhere(humanWriter, "requires member or admin role", next)
}

func getUserFromContext(r *http.Request) *model.User {
	val := r.Context().Value(userContextKey)
	if val == nil {
		return nil
	}
	user, ok := val.(*model.User)
	if !ok {
		return nil
	}
	return user
}
