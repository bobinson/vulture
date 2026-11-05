package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Credential precedence (feature 0102, CWE-922): a stream_token, then a
// Bearer header, then the session cookie. Request builders are in
// session_cookie_test.go.

// credTestOutcome is what credential returned for one request.
type credTestOutcome struct {
	token string
	kind  credKind
}

// TestCredential_BearerPathZeroAllocs: a Bearer request costs no allocation to
// classify, on a bare URL, with a query and with an id, because the query is
// parsed only when it may hold a stream_token.
func TestCredential_BearerPathZeroAllocs(t *testing.T) {
	m := NewAuthMiddleware(fakeAuthSvc{})
	for _, target := range []string{"/api/audits", "/api/audits?limit=10", "/api/audits/a-123"} {
		r := credTestBearer(http.MethodGet, target, "header.payload.sig")
		var got credTestOutcome
		allocs := testing.AllocsPerRun(100, func() { got.token, got.kind = m.credential(r) })
		if want := (credTestOutcome{"header.payload.sig", credBearer}); allocs != 0 || got != want {
			t.Errorf("%s: %v allocs, credential %+v; want 0 allocs and %+v", target, allocs, got, want)
		}
	}
}

// TestCredential_PercentEncodedStreamTokenNeverFallsThrough: a stream_token,
// however its key is spelled in the query and on whatever path, is the
// credential; when it does not validate the request is 401 even beside a
// valid Bearer token. A query with only other escapes still reaches the
// Bearer token.
func TestCredential_PercentEncodedStreamTokenNeverFallsThrough(t *testing.T) {
	_, mw, svc := setupLocalMode(t)
	jwt := credTestToken(t, svc)
	h := mw.Require(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	forged := credTestOutcome{"forged", credStream}
	for _, c := range []struct {
		target string
		want   credTestOutcome
		code   int
	}{
		{"/api/audits/a-1/stream?stream%5Ftoken=forged", forged, http.StatusUnauthorized},
		{"/api/audits/a-1/stream?stream%5ftoken=forged", forged, http.StatusUnauthorized},
		{"/api/audits?limit=10&stream%5Ftoken=forged", forged, http.StatusUnauthorized},
		{"/api/audits?stream_token=forged", forged, http.StatusUnauthorized},
		{"/api/audits?q=a%20b", credTestOutcome{jwt, credBearer}, http.StatusOK},
	} {
		r := credTestBearer(http.MethodGet, c.target, jwt)
		var got credTestOutcome
		got.token, got.kind = mw.credential(r)
		w := httptest.NewRecorder()
		h(w, r)
		if got != c.want || w.Code != c.code {
			t.Errorf("%s: credential %+v, status %d; want %+v and %d", c.target, got, w.Code, c.want, c.code)
		}
	}
}

// TestCsrfRefused_Table: only a cookie-authenticated unsafe request without
// the CSRF header is refused.
func TestCsrfRefused_Table(t *testing.T) {
	for _, c := range []struct {
		kind   credKind
		method string
		header bool
		want   bool
	}{
		{credCookie, http.MethodPost, false, true},
		{credCookie, http.MethodPut, false, true},
		{credCookie, http.MethodPatch, false, true},
		{credCookie, http.MethodDelete, false, true},
		{credCookie, http.MethodPost, true, false},
		{credCookie, http.MethodDelete, true, false},
		{credCookie, http.MethodGet, false, false},
		{credCookie, http.MethodHead, false, false},
		{credCookie, http.MethodOptions, false, false},
		{credBearer, http.MethodPost, false, false},
		{credStream, http.MethodPost, false, false},
		{credNone, http.MethodPost, false, false},
	} {
		r := httptest.NewRequest(c.method, "/api/sources", nil)
		if c.header {
			r.Header.Set("X-Vulture-CSRF", "1")
		}
		if got := csrfRefused(c.kind, r); got != c.want {
			t.Errorf("kind %d %s (CSRF header %t): got %t, want %t", c.kind, c.method, c.header, got, c.want)
		}
	}
}
