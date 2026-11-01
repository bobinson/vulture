//go:build e2e

package e2e

// Browser session cookie (feature 0102, CWE-922).
//
// The SPA no longer keeps a JWT where page scripts can read it. A login,
// registration or local session that carries X-Vulture-CSRF: 1 is answered
// with an HttpOnly, SameSite=Strict session cookie, and its body leaves the
// token out. Without that header the answer is unchanged, so the CLI, CI
// clients and scripts keep their body token and their Bearer header.
//
// The cookie is the credential of last resort:
//   - a stream_token or any Authorization header decides alone;
//   - an API key is never read from it;
//   - a same-site or cross-site fetch is treated as presenting no cookie;
//   - an unsafe request it authenticates must carry X-Vulture-CSRF;
//   - it cannot mint a credential (an API key, a user);
//   - POST /api/auth/logout deletes it.
//
// Over HTTPS (or behind a TLS proxy that sets X-Forwarded-Proto) the cookie is
// __Host-vulture_session and Secure. /api/auth/me reports only a principal
// that presented a credential, so local mode's implicit user gets 401 there.

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/config"
)

const (
	sessCSRFHeader = "X-Vulture-CSRF"
	sessCookieName = "vulture_session"
	sessHostCookie = "__Host-vulture_session"
	sessCSRFText   = "cookie-authenticated requests must send X-Vulture-CSRF; reload the page"
	sessBearerOnly = "this endpoint requires a bearer credential"
	sessLocalAdmin = "admin@vulture.local"
	sessPassword   = "session-password-1"
	// sessMaxAge is the session lifetime in seconds: the cookie's Max-Age and
	// the lifetime of the JWT inside it.
	sessMaxAge = 86400
	// sessLimitProbe bounds the requests sent to fill one rate-limit bucket.
	sessLimitProbe = 500
)

// sessCSRF is the header the SPA sends with every fetch.
var sessCSRF = map[string]string{sessCSRFHeader: "1"}

// sessClient has no cookie jar: every test states the cookies it sends.
var sessClient = &http.Client{Timeout: 15 * time.Second}

// sessReq is one request. cookie, when set, goes out as a Cookie header;
// header holds every other header to set.
type sessReq struct {
	method, path, body string
	cookie             *http.Cookie
	header             map[string]string
}

// sessReply is a response with its body read.
type sessReply struct {
	status  int
	header  http.Header
	cookies []*http.Cookie
	body    []byte
}

// sessServer is one running backend and its dedicated source root.
type sessServer struct{ addr, dbPath, root string }

// sessAuth is a login, register or local-session body: its top-level keys,
// the token (empty when absent) and the user's email.
type sessAuth struct {
	keys  map[string]json.RawMessage
	token string
	email string
}

// sessCookieAttrs are the attributes the session contract fixes.
type sessCookieAttrs struct {
	path, domain     string
	httpOnly, secure bool
	sameSite         http.SameSite
}

// sessModeB starts a centralized server (ciTestConfig: real auth, API keys
// on, open registration) with a dedicated source root, after mutate (when
// non-nil) adjusts the config.
func sessModeB(t *testing.T, mutate func(*config.Config)) sessServer {
	t.Helper()
	cfg, dbPath := ciTestConfig(t)
	cfg.SourceRoot = browseRoot(t)
	if mutate != nil {
		mutate(cfg)
	}
	addr, cleanup := startTestServer(t, cfg)
	t.Cleanup(cleanup)
	return sessServer{addr: addr, dbPath: dbPath, root: cfg.SourceRoot}
}

// sessJSON encodes v as a request body.
func sessJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// sessBearer is the header set of a Bearer client.
func sessBearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// sessNewRequest builds r against the server at addr.
func sessNewRequest(t *testing.T, addr string, r sessReq) *http.Request {
	t.Helper()
	req, err := http.NewRequest(r.method, "http://"+addr+r.path, strings.NewReader(r.body))
	if err != nil {
		t.Fatalf("%s %s: %v", r.method, r.path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range r.header {
		req.Header.Set(k, v)
	}
	if r.cookie != nil {
		req.AddCookie(r.cookie)
	}
	return req
}

// sessOpen sends r and returns the live response; the caller closes its body.
func sessOpen(t *testing.T, addr string, r sessReq) *http.Response {
	t.Helper()
	resp, err := sessClient.Do(sessNewRequest(t, addr, r))
	if err != nil {
		t.Fatalf("%s %s: %v", r.method, r.path, err)
	}
	return resp
}

// sessDo sends r and returns the response with its body read.
func sessDo(t *testing.T, addr string, r sessReq) sessReply {
	t.Helper()
	resp := sessOpen(t, addr, r)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s: %v", r.method, r.path, err)
	}
	return sessReply{status: resp.StatusCode, header: resp.Header, cookies: resp.Cookies(), body: body}
}

// sessWantStatus fails the test unless rep has status.
func sessWantStatus(t *testing.T, what string, rep sessReply, status int) {
	t.Helper()
	if rep.status != status {
		t.Errorf("%s: got %d %.300s; want %d", what, rep.status, rep.body, status)
	}
}

// sessWantError fails the test unless rep is status with exactly
// {"error": msg}.
func sessWantError(t *testing.T, what string, rep sessReply, status int, msg string) {
	t.Helper()
	var got map[string]string
	_ = json.Unmarshal(rep.body, &got)
	if rep.status != status || len(got) != 1 || got["error"] != msg {
		t.Errorf("%s: got %d %.300s; want %d {\"error\":%q}", what, rep.status, rep.body, status, msg)
	}
}

// sessAuthOf parses rep as an auth response, failing the test when it is not
// one.
func sessAuthOf(t *testing.T, what string, rep sessReply) sessAuth {
	t.Helper()
	var a sessAuth
	var user struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(rep.body, &a.keys) != nil || json.Unmarshal(a.keys["user"], &user) != nil {
		t.Fatalf("%s: not an auth response: %d %.300s", what, rep.status, rep.body)
	}
	_ = json.Unmarshal(a.keys["token"], &a.token)
	a.email = user.Email
	return a
}

// sessWantTokenInBody: the Bearer-client answer carries the user and a
// non-empty token.
func sessWantTokenInBody(t *testing.T, what string, rep sessReply, email string) {
	t.Helper()
	if a := sessAuthOf(t, what, rep); a.token == "" || a.email != email {
		t.Errorf("%s: body %.300s; want user %s and a token", what, rep.body, email)
	}
}

// sessWantNoTokenInBody: the cookie answer carries the user and no "token"
// key at all.
func sessWantNoTokenInBody(t *testing.T, what string, rep sessReply, email string) {
	t.Helper()
	a := sessAuthOf(t, what, rep)
	if _, has := a.keys["token"]; has || a.email != email {
		t.Errorf("%s: body %.300s; want user %s and no token key", what, rep.body, email)
	}
}

// sessWantNoStore: a response that carries a session is never cached.
func sessWantNoStore(t *testing.T, what string, rep sessReply) {
	t.Helper()
	if cc := rep.header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("%s: Cache-Control %q; want no-store", what, cc)
	}
}

// sessWantNoCookies: rep sets no cookie at all.
func sessWantNoCookies(t *testing.T, what string, rep sessReply) {
	t.Helper()
	if len(rep.cookies) != 0 {
		t.Errorf("%s: Set-Cookie %q; want none", what, rep.header.Values("Set-Cookie"))
	}
}

// sessWantNoCookie: rep sets no cookie named name.
func sessWantNoCookie(t *testing.T, what string, rep sessReply, name string) {
	t.Helper()
	for _, c := range rep.cookies {
		if c.Name == name {
			t.Errorf("%s: sets %s; want no such cookie", what, name)
		}
	}
}

// sessCookieOf returns the one cookie named name that rep sets, failing the
// test when there is none or more than one.
func sessCookieOf(t *testing.T, what string, rep sessReply, name string) *http.Cookie {
	t.Helper()
	var found []*http.Cookie
	for _, c := range rep.cookies {
		if c.Name == name {
			found = append(found, c)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: want exactly one %s cookie, got %d (status %d, Set-Cookie %q)",
			what, name, len(found), rep.status, rep.header.Values("Set-Cookie"))
	}
	return found[0]
}

func sessAttrs(c *http.Cookie) sessCookieAttrs {
	return sessCookieAttrs{c.Path, c.Domain, c.HttpOnly, c.Secure, c.SameSite}
}

// sessWantAttrs are the session cookie's attributes: HttpOnly,
// SameSite=Strict, host-only, Path=/, Secure exactly when secure.
func sessWantAttrs(secure bool) sessCookieAttrs {
	return sessCookieAttrs{"/", "", true, secure, http.SameSiteStrictMode}
}

// sessWantIssued: c carries a session: sessWantAttrs, Max-Age the session
// lifetime and a value.
func sessWantIssued(t *testing.T, what string, c *http.Cookie, secure bool) {
	t.Helper()
	want := sessWantAttrs(secure)
	if sessAttrs(c) != want || c.MaxAge != sessMaxAge || c.Value == "" {
		t.Errorf("%s: %s %+v Max-Age %d (empty value %t); want %+v Max-Age %d and a value",
			what, c.Name, sessAttrs(c), c.MaxAge, c.Value == "", want, sessMaxAge)
	}
}

// sessWantCleared: c deletes the session: sessWantAttrs, an empty value and
// Max-Age=0 on the wire (MaxAge < 0 once parsed).
func sessWantCleared(t *testing.T, what string, c *http.Cookie, secure bool) {
	t.Helper()
	want := sessWantAttrs(secure)
	if sessAttrs(c) != want || c.MaxAge >= 0 || c.Value != "" {
		t.Errorf("%s: %s=%q %+v MaxAge %d; want an empty value, %+v and MaxAge < 0",
			what, c.Name, c.Value, sessAttrs(c), c.MaxAge, want)
	}
}

// sessWantSession checks a sign-in sent with the CSRF header and returns its
// session cookie: status, the user in the body without a token, no caching,
// and an issued cookie named name (Secure when it is the __Host- name).
func sessWantSession(t *testing.T, what string, rep sessReply, status int, email, name string) *http.Cookie {
	t.Helper()
	sessWantStatus(t, what, rep, status)
	sessWantNoTokenInBody(t, what, rep, email)
	sessWantNoStore(t, what, rep)
	c := sessCookieOf(t, what, rep, name)
	sessWantIssued(t, what, c, name == sessHostCookie)
	return c
}

// sessJWTExp returns the exp claim of jwt.
func sessJWTExp(t *testing.T, jwt string) int64 {
	t.Helper()
	_, rest, _ := strings.Cut(jwt, ".")
	payload, _, _ := strings.Cut(rest, ".")
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err != nil || json.Unmarshal(raw, &claims) != nil {
		t.Fatalf("session cookie value is not a JWT with an exp claim")
	}
	return claims.Exp
}

// sessWantJWTLifetime: the JWT in the cookie expires when the cookie does,
// so the two cannot drift apart.
func sessWantJWTLifetime(t *testing.T, jwt string, issued time.Time) {
	t.Helper()
	want := issued.Add(sessMaxAge * time.Second).Unix()
	if d := sessJWTExp(t, jwt) - want; d < -1 || d > 5 {
		t.Errorf("JWT exp is %ds off the cookie's Max-Age from issue", d)
	}
}

// sessRegisterBody is a registration of email.
func sessRegisterBody(email string) string {
	return sessJSON(map[string]string{"email": email, "password": sessPassword, "name": "Session User"})
}

// sessLogin posts email's credentials to /api/auth/login with header.
func sessLogin(t *testing.T, addr, email string, header map[string]string) sessReply {
	t.Helper()
	body := sessJSON(map[string]string{"email": email, "password": sessPassword})
	return sessDo(t, addr, sessReq{method: http.MethodPost, path: "/api/auth/login", body: body, header: header})
}

// sessSignIn logs email in as the SPA does and returns the session cookie.
func sessSignIn(t *testing.T, addr, email string) *http.Cookie {
	t.Helper()
	return sessCookieOf(t, "login with the CSRF header", sessLogin(t, addr, email, sessCSRF), sessCookieName)
}

// sessMember registers email as a member of s and returns its session cookie.
func sessMember(t *testing.T, s sessServer, email string) *http.Cookie {
	t.Helper()
	registerAndLogin(t, s.addr, s.dbPath, email, sessPassword, false)
	return sessSignIn(t, s.addr, email)
}

// sessLogout posts /api/auth/logout with cookie (when non-nil) and header.
func sessLogout(t *testing.T, addr string, cookie *http.Cookie, header map[string]string) sessReply {
	t.Helper()
	return sessDo(t, addr, sessReq{method: http.MethodPost, path: "/api/auth/logout", cookie: cookie, header: header})
}

// sessMe GETs /api/auth/me with r's cookie and headers.
func sessMe(t *testing.T, addr string, r sessReq) sessReply {
	t.Helper()
	r.method, r.path = http.MethodGet, "/api/auth/me"
	return sessDo(t, addr, r)
}

// sessWantMe fails the test unless /api/auth/me, sent as r, answers 200 with
// the user email.
func sessWantMe(t *testing.T, what, addr string, r sessReq, email string) {
	t.Helper()
	rep := sessMe(t, addr, r)
	var u struct {
		Email string `json:"email"`
	}
	_ = json.Unmarshal(rep.body, &u)
	if rep.status != http.StatusOK || u.Email != email {
		t.Errorf("%s: /api/auth/me got %d %.300s; want 200 for %s", what, rep.status, rep.body, email)
	}
}

// sessSourceDir creates a one-file source directory inside root.
func sessSourceDir(t *testing.T, root string) string {
	t.Helper()
	dir := localIngestMkdir(t, filepath.Join(root, "src"))
	localIngestFile(t, filepath.Join(dir, "main.go"))
	return dir
}

// sessSourceBody is an ingest request for a local source inside root.
func sessSourceBody(t *testing.T, root string) string {
	t.Helper()
	return sessJSON(map[string]string{"type": "local", "path": sessSourceDir(t, root)})
}

// sessFetchSite is the header set of a browser request marked site, or none
// for a client that sends no Sec-Fetch-Site.
func sessFetchSite(site string) map[string]string {
	if site == "" {
		return nil
	}
	return map[string]string{"Sec-Fetch-Site": site}
}

// sessStreamToken mints a stream token for auditID with the session cookie,
// as the SPA does before it opens the EventSource.
func sessStreamToken(t *testing.T, addr, auditID string, cookie *http.Cookie) string {
	t.Helper()
	rep := sessDo(t, addr, sessReq{method: http.MethodPost, path: "/api/audits/" + auditID + "/stream-token",
		cookie: cookie, header: sessCSRF})
	var body struct {
		StreamToken string `json:"stream_token"`
	}
	_ = json.Unmarshal(rep.body, &body)
	if rep.status != http.StatusOK || body.StreamToken == "" {
		t.Fatalf("stream-token with the session cookie: got %d %.300s; want 200 with a token", rep.status, rep.body)
	}
	return body.StreamToken
}

// sessStreamStatus opens the audit stream as path (query included) with
// cookie (when non-nil) and returns the status, without reading the stream.
func sessStreamStatus(t *testing.T, addr, path string, cookie *http.Cookie) int {
	t.Helper()
	resp := sessOpen(t, addr, sessReq{method: http.MethodGet, path: path, cookie: cookie})
	_ = resp.Body.Close()
	return resp.StatusCode
}

// sessExhaust sends cookie's GETs to path until the rate limiter answers 429,
// failing the test when it does not within sessLimitProbe requests.
func sessExhaust(t *testing.T, addr, path string, cookie *http.Cookie) {
	t.Helper()
	for i := 0; i < sessLimitProbe; i++ {
		if sessDo(t, addr, sessReq{method: http.MethodGet, path: path, cookie: cookie}).status == http.StatusTooManyRequests {
			return
		}
	}
	t.Fatalf("%s: %d cookie requests never reached the rate limit", path, sessLimitProbe)
}

// sessMaskedFinding runs a local-mode audit whose one finding masks a token
// that is still in the scanned file, and returns the server and the
// finding's masked-values path.
func sessMaskedFinding(t *testing.T) (addr, path string) {
	t.Helper()
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": newScriptedAgent(t, maskedFindingResult(t))})
	src := localIngestMkdir(t, filepath.Join(h.dir, "src"))
	content := "const a = 1;\nconst token = \"" + maskedJWT0074 + "\";\n"
	if err := os.WriteFile(filepath.Join(src, "config.ts"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	a := h.run(t, []string{"cwe"}, nil)
	if len(a.Findings) != 1 {
		t.Fatalf("persisted %d findings, want 1", len(a.Findings))
	}
	return h.addr, "/api/audits/" + a.ID + "/findings/" + a.Findings[0].ID + "/masked"
}

// TestSession_LoginWithHeaderSetsHttpOnlyStrictCookie: a login carrying the
// CSRF header gets its session as an HttpOnly, SameSite=Strict, host-only
// cookie for "/" that lives exactly as long as the JWT inside it, and over
// plain HTTP it is not Secure. The body keeps the user and drops the token,
// and the answer is never cached.
func TestSession_LoginWithHeaderSetsHttpOnlyStrictCookie(t *testing.T) {
	s := sessModeB(t, nil)
	registerAndLogin(t, s.addr, s.dbPath, "cookie@example.test", sessPassword, false)
	issued := time.Now()
	rep := sessLogin(t, s.addr, "cookie@example.test", sessCSRF)
	sessWantNoCookie(t, "login over HTTP", rep, sessHostCookie)
	c := sessWantSession(t, "login with the CSRF header", rep, http.StatusOK, "cookie@example.test", sessCookieName)
	sessWantJWTLifetime(t, c.Value, issued)
}

// TestSession_LoginWithoutHeaderUnchanged: a login without the CSRF header
// (the CLI, CI, scripts) is answered as before: the token is in the body and
// no cookie is set.
func TestSession_LoginWithoutHeaderUnchanged(t *testing.T) {
	s := sessModeB(t, nil)
	registerAndLogin(t, s.addr, s.dbPath, "cli@example.test", sessPassword, false)
	rep := sessLogin(t, s.addr, "cli@example.test", nil)
	sessWantStatus(t, "login without the CSRF header", rep, http.StatusOK)
	sessWantTokenInBody(t, "login without the CSRF header", rep, "cli@example.test")
	sessWantNoCookies(t, "login without the CSRF header", rep)
}

// TestSession_CookieAuthenticatesMe: the cookie alone authenticates, whether a
// registration or a login issued it.
func TestSession_CookieAuthenticatesMe(t *testing.T) {
	s := sessModeB(t, nil)
	const email = "me@example.test"
	reg := sessDo(t, s.addr, sessReq{method: http.MethodPost, path: "/api/auth/register",
		body: sessRegisterBody(email), header: sessCSRF})
	regCookie := sessWantSession(t, "register with the CSRF header", reg, http.StatusCreated, email, sessCookieName)
	sessWantMe(t, "the registration's cookie", s.addr, sessReq{cookie: regCookie}, email)
	sessWantMe(t, "the login's cookie", s.addr, sessReq{cookie: sessSignIn(t, s.addr, email)}, email)
}

// TestSession_CookieUnsafeWithoutHeaderIs403: a state-changing request that
// only the cookie authenticates is refused with a fixed text that tells the
// user to reload; with the CSRF header it is served.
func TestSession_CookieUnsafeWithoutHeaderIs403(t *testing.T) {
	s := sessModeB(t, nil)
	cookie := sessMember(t, s, "writer@example.test")
	body := sessSourceBody(t, s.root)
	bare := sessDo(t, s.addr, sessReq{method: http.MethodPost, path: "/api/sources", body: body, cookie: cookie})
	sessWantError(t, "cookie POST without the CSRF header", bare, http.StatusForbidden, sessCSRFText)
	withHeader := sessDo(t, s.addr, sessReq{method: http.MethodPost, path: "/api/sources", body: body,
		cookie: cookie, header: sessCSRF})
	sessWantStatus(t, "cookie POST with the CSRF header", withHeader, http.StatusCreated)
}

// TestSession_BearerUnsafeWithoutHeaderAllowed: Bearer clients, with a JWT or
// an API key, never send the CSRF header and keep writing.
func TestSession_BearerUnsafeWithoutHeaderAllowed(t *testing.T) {
	s := sessModeB(t, nil)
	admin := registerAndLogin(t, s.addr, s.dbPath, "bearer@example.test", sessPassword, true)
	body := sessSourceBody(t, s.root)
	for name, token := range map[string]string{"JWT": admin, "API key": mintBrowseAPIKey(t, s.addr, admin)} {
		rep := sessDo(t, s.addr, sessReq{method: http.MethodPost, path: "/api/sources", body: body, header: sessBearer(token)})
		sessWantStatus(t, name+" Bearer POST without the CSRF header", rep, http.StatusCreated)
	}
}

// TestSession_BadBearerDoesNotFallThroughToCookie: an Authorization header
// decides alone. A bad one is 401 even beside a valid cookie.
func TestSession_BadBearerDoesNotFallThroughToCookie(t *testing.T) {
	s := sessModeB(t, nil)
	cookie := sessMember(t, s, "fallthrough@example.test")
	for _, auth := range []string{"Bearer not-a-jwt", "Bearer vk_not_a_key", "Basic c2Vzc2lvbjp1c2Vy"} {
		rep := sessMe(t, s.addr, sessReq{cookie: cookie, header: map[string]string{"Authorization": auth}})
		sessWantStatus(t, auth+" beside a valid cookie", rep, http.StatusUnauthorized)
	}
	sessWantMe(t, "the same cookie alone", s.addr, sessReq{cookie: cookie}, "fallthrough@example.test")
}

// TestSession_APIKeyInCookieRejected: an API key is a Bearer credential only.
// Carried in either session cookie, a valid key authenticates nothing.
func TestSession_APIKeyInCookieRejected(t *testing.T) {
	s := sessModeB(t, nil)
	admin := registerAndLogin(t, s.addr, s.dbPath, "keys@example.test", sessPassword, true)
	key := mintBrowseAPIKey(t, s.addr, admin)
	sessWantStatus(t, "the key as a Bearer", sessMe(t, s.addr, sessReq{header: sessBearer(key)}), http.StatusOK)
	for _, name := range []string{sessCookieName, sessHostCookie} {
		rep := sessMe(t, s.addr, sessReq{cookie: &http.Cookie{Name: name, Value: key}})
		sessWantStatus(t, "the key in the "+name+" cookie", rep, http.StatusUnauthorized)
	}
}

// TestSession_LogoutClearsCookie: logout needs the CSRF header (403 and no
// cookie change without it). With it, the answer is a bodiless 204 whose
// Set-Cookie deletes the session; it is idempotent, so a request without a
// session gets the same answer.
func TestSession_LogoutClearsCookie(t *testing.T) {
	s := sessModeB(t, nil)
	sessWantError(t, "logout without the CSRF header", sessLogout(t, s.addr, nil, nil), http.StatusForbidden, sessCSRFText)
	cookie := sessMember(t, s, "logout@example.test")
	bare := sessLogout(t, s.addr, cookie, nil)
	sessWantError(t, "cookie logout without the CSRF header", bare, http.StatusForbidden, sessCSRFText)
	sessWantNoCookies(t, "cookie logout without the CSRF header", bare)
	for _, c := range []*http.Cookie{cookie, nil} {
		rep := sessLogout(t, s.addr, c, sessCSRF)
		sessWantStatus(t, "logout with the CSRF header", rep, http.StatusNoContent)
		sessWantCleared(t, "logout with the CSRF header", sessCookieOf(t, "logout", rep, sessCookieName), false)
		if len(rep.body) != 0 {
			t.Errorf("logout 204 has a body: %q", rep.body)
		}
	}
}

// TestSession_HTTPSUsesHostPrefixAndSecure: behind a TLS proxy
// (X-Forwarded-Proto: https) the cookie is __Host-vulture_session and Secure.
// That name is accepted on any request, the plain name only on a plain HTTP
// one, and logout deletes the __Host- cookie.
func TestSession_HTTPSUsesHostPrefixAndSecure(t *testing.T) {
	s := sessModeB(t, nil)
	const email = "tls@example.test"
	registerAndLogin(t, s.addr, s.dbPath, email, sessPassword, false)
	https := map[string]string{"X-Forwarded-Proto": "https"}
	httpsCSRF := map[string]string{"X-Forwarded-Proto": "https", sessCSRFHeader: "1"}
	rep := sessLogin(t, s.addr, email, httpsCSRF)
	sessWantNoCookie(t, "login over HTTPS", rep, sessCookieName)
	c := sessWantSession(t, "login over HTTPS", rep, http.StatusOK, email, sessHostCookie)
	sessWantMe(t, "__Host- cookie over HTTPS", s.addr, sessReq{cookie: c, header: https}, email)
	sessWantMe(t, "__Host- cookie over HTTP", s.addr, sessReq{cookie: c}, email)
	plain := &http.Cookie{Name: sessCookieName, Value: c.Value}
	sessWantStatus(t, "plain-name cookie over HTTPS", sessMe(t, s.addr, sessReq{cookie: plain, header: https}), http.StatusUnauthorized)
	out := sessLogout(t, s.addr, c, httpsCSRF)
	sessWantStatus(t, "logout over HTTPS", out, http.StatusNoContent)
	sessWantCleared(t, "logout over HTTPS", sessCookieOf(t, "logout over HTTPS", out, sessHostCookie), true)
}

// TestSession_LocalMode_SessionCookieAndMe401: in local mode the SPA's session
// comes from local-session, which with the CSRF header is a cookie too, and
// without it still a body token. /api/auth/me answers only a request that
// presented a credential: the implicit local user gets 401 there, so the SPA
// knows to ask for a session.
func TestSession_LocalMode_SessionCookieAndMe401(t *testing.T) {
	addr, cleanup := startTestServer(t, testConfig(t))
	defer cleanup()
	plain := sessDo(t, addr, sessReq{method: http.MethodGet, path: "/api/auth/local-session"})
	sessWantStatus(t, "local-session without the CSRF header", plain, http.StatusOK)
	sessWantTokenInBody(t, "local-session without the CSRF header", plain, sessLocalAdmin)
	sessWantNoCookies(t, "local-session without the CSRF header", plain)
	sessWantStatus(t, "/api/auth/me with no credential", sessMe(t, addr, sessReq{}), http.StatusUnauthorized)
	rep := sessDo(t, addr, sessReq{method: http.MethodGet, path: "/api/auth/local-session", header: sessCSRF})
	c := sessWantSession(t, "local-session with the CSRF header", rep, http.StatusOK, sessLocalAdmin, sessCookieName)
	sessWantMe(t, "the local session cookie", addr, sessReq{cookie: c}, sessLocalAdmin)
}

// TestSession_LocalMode_MaskedValuesWithCookie: masked values go to a request
// that presented a credential, and the session cookie is one, so the SPA keeps
// receiving them in local mode. A request presenting nothing still does not.
func TestSession_LocalMode_MaskedValuesWithCookie(t *testing.T) {
	addr, path := sessMaskedFinding(t)
	none := sessDo(t, addr, sessReq{method: http.MethodGet, path: path})
	if strings.Contains(string(none.body), maskedJWT0074) {
		t.Errorf("a request presenting no credential received the value: %s", none.body)
	}
	session := sessDo(t, addr, sessReq{method: http.MethodGet, path: "/api/auth/local-session", header: sessCSRF})
	cookie := sessCookieOf(t, "local-session with the CSRF header", session, sessCookieName)
	rep := sessDo(t, addr, sessReq{method: http.MethodGet, path: path, cookie: cookie})
	if rep.status != http.StatusOK || !strings.Contains(string(rep.body), maskedJWT0074) {
		t.Errorf("the session cookie on loopback must receive the value: %d %.300s", rep.status, rep.body)
	}
}

// TestSession_StreamTokenViaCookie: the SPA mints its single-use stream token
// with the cookie (and the CSRF header: it is a POST), then opens the stream
// with that token alone, as EventSource does. A stream_token that does not
// validate is refused even beside a valid cookie.
func TestSession_StreamTokenViaCookie(t *testing.T) {
	agent := newScriptedAgent(t, `{"findings":[],"summary":"cwe","score":100}`)
	s := sessModeB(t, func(c *config.Config) {
		c.Agents = map[string]config.AgentConfig{"cwe": {Name: "CWE", Type: "cwe", URL: agent.srv.URL}}
	})
	const email = "stream@example.test"
	bearer := registerAndLogin(t, s.addr, s.dbPath, email, sessPassword, false)
	src := localIngestAs(t, s.addr, bearer, sessSourceDir(t, s.root))
	if src.srcID == "" {
		t.Fatalf("Bearer ingest: got %d %.300s; want a source id", src.status, src.body)
	}
	audit := localIngestRunAudit(t, s.addr, bearer, src.srcID)
	cookie := sessSignIn(t, s.addr, email)
	stream := "/api/audits/" + audit.ID + "/stream?stream_token="
	if got := sessStreamStatus(t, s.addr, stream+"forged-stream-token", cookie); got != http.StatusUnauthorized {
		t.Errorf("forged stream_token beside a valid cookie: got %d; want 401", got)
	}
	token := sessStreamToken(t, s.addr, audit.ID, cookie)
	if got := sessStreamStatus(t, s.addr, stream+url.QueryEscape(token), nil); got != http.StatusOK {
		t.Errorf("stream GET with the minted stream_token: got %d; want 200", got)
	}
}

// TestSession_ReadOnly_LoginLogout: a read-only viewer still signs users in
// and out with the cookie, and its writes stay refused.
func TestSession_ReadOnly_LoginLogout(t *testing.T) {
	s := sessModeB(t, func(c *config.Config) { c.ReadOnly = true })
	cookie := sessMember(t, s, "viewer@example.test")
	sessWantMe(t, "the cookie on a read-only server", s.addr, sessReq{cookie: cookie}, "viewer@example.test")
	write := sessDo(t, s.addr, sessReq{method: http.MethodPost, path: "/api/sources", body: sessSourceBody(t, s.root),
		cookie: cookie, header: sessCSRF})
	sessWantStatus(t, "a cookie write on a read-only server", write, http.StatusServiceUnavailable)
	out := sessLogout(t, s.addr, cookie, sessCSRF)
	sessWantStatus(t, "logout on a read-only server", out, http.StatusNoContent)
	sessWantCleared(t, "logout on a read-only server", sessCookieOf(t, "read-only logout", out, sessCookieName), false)
}

// TestSession_RateLimitKeyedOnPrincipal: the per-principal limits on
// /api/audits and /api/findings/ key on who signed in, not on the
// Authorization header, so two cookie users behind one IP do not share a
// bucket.
func TestSession_RateLimitKeyedOnPrincipal(t *testing.T) {
	s := sessModeB(t, nil)
	first := sessMember(t, s, "first@example.test")
	second := sessMember(t, s, "second@example.test")
	for _, path := range []string{"/api/audits", "/api/findings/sess-finding/label"} {
		sessExhaust(t, s.addr, path, first)
		rep := sessDo(t, s.addr, sessReq{method: http.MethodGet, path: path, cookie: second})
		if rep.status == http.StatusTooManyRequests || rep.status == http.StatusUnauthorized {
			t.Errorf("%s: the second user got %d after the first was limited; want its own bucket", path, rep.status)
		}
	}
}

// TestSession_CookieCannotMintCredentials: an admin's cookie, even with the
// CSRF header, cannot reach the routes that mint or manage credentials (API
// keys, users), so a page cannot turn the session into a credential that
// outlives it. The same admin's Bearer token can, and creating a user never
// signs anyone in by cookie.
func TestSession_CookieCannotMintCredentials(t *testing.T) {
	s := sessModeB(t, nil)
	admin := registerAndLogin(t, s.addr, s.dbPath, "admin@example.test", sessPassword, true)
	cookie := sessSignIn(t, s.addr, "admin@example.test")
	keyBody, userBody := sessJSON(map[string]string{"name": "from-the-browser"}), sessRegisterBody("created@example.test")
	for _, r := range []sessReq{
		{method: http.MethodPost, path: "/api/api-keys", body: keyBody},
		{method: http.MethodGet, path: "/api/api-keys"},
		{method: http.MethodDelete, path: "/api/api-keys/sess-no-such-key"},
		{method: http.MethodPost, path: "/api/admin/users", body: userBody},
	} {
		r.cookie, r.header = cookie, sessCSRF
		sessWantError(t, "admin cookie "+r.method+" "+r.path, sessDo(t, s.addr, r), http.StatusForbidden, sessBearerOnly)
	}
	bearerCSRF := sessBearer(admin)
	bearerCSRF[sessCSRFHeader] = "1"
	for _, r := range []sessReq{
		{method: http.MethodPost, path: "/api/api-keys", body: keyBody, header: bearerCSRF},
		{method: http.MethodPost, path: "/api/admin/users", body: userBody, header: bearerCSRF},
	} {
		rep := sessDo(t, s.addr, r)
		sessWantStatus(t, "admin Bearer POST "+r.path, rep, http.StatusCreated)
		sessWantNoCookies(t, "admin Bearer POST "+r.path, rep)
	}
}

// TestSession_PreflightDoesNotApproveCSRFHeader: the CORS preflight never
// approves X-Vulture-CSRF, so an allowlisted cross-origin page cannot send it
// with the user's cookie; only the same-origin SPA can.
func TestSession_PreflightDoesNotApproveCSRFHeader(t *testing.T) {
	const origin = "https://app.example.test"
	s := sessModeB(t, func(c *config.Config) { c.CORSAllowedOrigins = []string{origin} })
	rep := sessDo(t, s.addr, sessReq{method: http.MethodOptions, path: "/api/sources", header: map[string]string{
		"Origin": origin, "Access-Control-Request-Method": http.MethodPost, "Access-Control-Request-Headers": "x-vulture-csrf",
	}})
	allowed := strings.ToLower(rep.header.Get("Access-Control-Allow-Headers"))
	if rep.header.Get("Access-Control-Allow-Origin") != origin || strings.Contains(allowed, "x-vulture-csrf") {
		t.Errorf("preflight from the allowlisted origin: Allow-Origin %q, Allow-Headers %q; want the origin and no x-vulture-csrf",
			rep.header.Get("Access-Control-Allow-Origin"), allowed)
	}
}

// TestSession_CookieIgnoredOnSameSiteFetch: the cookie is read only on a
// request the browser marks same-origin or user-initiated ("none"), or one
// with no Sec-Fetch-Site at all (a non-browser client). A same-site or
// cross-site request is treated as presenting no cookie.
func TestSession_CookieIgnoredOnSameSiteFetch(t *testing.T) {
	s := sessModeB(t, nil)
	cookie := sessMember(t, s, "site@example.test")
	for _, c := range []struct {
		site string
		want int
	}{
		{"", http.StatusOK}, {"same-origin", http.StatusOK}, {"none", http.StatusOK},
		{"same-site", http.StatusUnauthorized}, {"cross-site", http.StatusUnauthorized},
	} {
		rep := sessMe(t, s.addr, sessReq{cookie: cookie, header: sessFetchSite(c.site)})
		sessWantStatus(t, "cookie with Sec-Fetch-Site "+c.site, rep, c.want)
	}
}
