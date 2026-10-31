package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

// Session cookie helpers (feature 0102, CWE-922). The test-only names here
// start with credTest or rateKeyTest so they cannot collide with the helpers
// under test.

// credTestToken issues a real JWT for the seeded user of setupLocalMode.
func credTestToken(t *testing.T, svc service.AuthService) string {
	t.Helper()
	resp, err := svc.IssueLocalAdminToken()
	if err != nil || resp.Token == "" {
		t.Fatalf("issue token: %v", err)
	}
	return resp.Token
}

// credTestBearer is method target with "Authorization: Bearer token".
func credTestBearer(method, target, token string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// credTestCookie is method target as the SPA sends it over plain HTTP: the
// session cookie and the CSRF header.
func credTestCookie(method, target, jwt string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.AddCookie(&http.Cookie{Name: "vulture_session", Value: jwt})
	r.Header.Set("X-Vulture-CSRF", "1")
	return r
}

// rateKeyTestRequest is a request whose context principal is u (none when
// nil) and whose Authorization header is auth (none when empty).
func rateKeyTestRequest(u *model.User, auth string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/audits", nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	if u != nil {
		r = r.WithContext(context.WithValue(r.Context(), userContextKey, u))
	}
	return r
}

// TestIsHTTPSRequest: TLS on this hop, or a TLS proxy's X-Forwarded-Proto
// (case-insensitive, as HSTS has always matched it).
func TestIsHTTPSRequest(t *testing.T) {
	for _, c := range []struct {
		target, proto string
		want          bool
	}{
		{"https://vulture.example/api/audits", "", true},
		{"https://vulture.example/api/audits", "http", true},
		{"http://vulture.example/api/audits", "https", true},
		{"http://vulture.example/api/audits", "HTTPS", true},
		{"http://vulture.example/api/audits", "http", false},
		{"http://vulture.example/api/audits", "", false},
	} {
		r := httptest.NewRequest(http.MethodGet, c.target, nil)
		if c.proto != "" {
			r.Header.Set("X-Forwarded-Proto", c.proto)
		}
		if got := IsHTTPSRequest(r); got != c.want {
			t.Errorf("%s with X-Forwarded-Proto %q: got %t, want %t", c.target, c.proto, got, c.want)
		}
	}
}

// TestPrincipalRateKey: the rate-limit key is the context principal, never
// the Authorization header; no principal means "" (the caller falls back to
// the client IP). MaskedValuesRateKey keys the same way.
func TestPrincipalRateKey(t *testing.T) {
	member := &model.User{ID: "u-1", Role: "member"}
	apiKey := &model.User{ID: "apikey:k-9", Role: "apikey"}
	for _, c := range []struct {
		name string
		r    *http.Request
		want string
	}{
		{"cookie or implicit principal", rateKeyTestRequest(member, ""), "user:u-1"},
		{"bearer principal", rateKeyTestRequest(member, "Bearer token-a"), "user:u-1"},
		{"same principal, another token", rateKeyTestRequest(member, "Bearer token-b"), "user:u-1"},
		{"api key principal", rateKeyTestRequest(apiKey, "Bearer vk_abc"), "user:apikey:k-9"},
		{"no principal, header present", rateKeyTestRequest(nil, "Bearer vk_abc"), ""},
		{"no principal", rateKeyTestRequest(nil, ""), ""},
	} {
		got := PrincipalRateKey(c.r)
		if masked := MaskedValuesRateKey(c.r); got != c.want || masked != got {
			t.Errorf("%s: PrincipalRateKey %q, MaskedValuesRateKey %q; want %q for both", c.name, got, masked, c.want)
		}
	}
}

// TestRequireBearerCredential: behind Require, a cookie-authenticated request
// is refused on every method, even with the CSRF header; the same principal's
// Bearer token passes.
func TestRequireBearerCredential(t *testing.T) {
	_, mw, svc := setupLocalMode(t)
	jwt := credTestToken(t, svc)
	h := mw.Require(RequireBearerCredential(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		w := httptest.NewRecorder()
		h(w, credTestCookie(method, "/api/api-keys", jwt))
		respErrWantStatus(t, w, http.StatusForbidden)
		respErrWantBody(t, w, map[string]string{"error": "this endpoint requires a bearer credential"})

		w = httptest.NewRecorder()
		h(w, credTestBearer(method, "/api/api-keys", jwt))
		if w.Code != http.StatusCreated {
			t.Errorf("%s with a Bearer token: got %d %s, want 201", method, w.Code, w.Body.String())
		}
	}
}
