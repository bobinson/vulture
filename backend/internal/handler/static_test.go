package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func newTestFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":     &fstest.MapFile{Data: []byte("<html>SPA</html>")},
		"assets/app.js":  &fstest.MapFile{Data: []byte("console.log('app');")},
		"assets/app.css": &fstest.MapFile{Data: []byte("body{}")},
	}
}

func TestIsAPIPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/api/audits", true},
		{"/api/", true},
		{"/api", true},
		{"/health", true},
		{"/health/ready", true},
		{"/metrics", true},
		{"/debug/pprof", true},
		{"/", false},
		{"/index.html", false},
		{"/assets/app.js", false},
		{"/api-not-a-route-prefix", false}, // missing slash after "api"
		{"/api2", false},                   // not API surface
	}
	for _, tc := range cases {
		if got := IsAPIPath(tc.path); got != tc.want {
			t.Errorf("IsAPIPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestStaticHandlerServesIndex(t *testing.T) {
	h := StaticHandler(newTestFS())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET / status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "SPA") {
		t.Errorf("GET / body = %q, want SPA contents", w.Body.String())
	}
}

func TestStaticHandlerServesAsset(t *testing.T) {
	h := StaticHandler(newTestFS())
	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "console.log") {
		t.Errorf("body did not contain asset contents: %q", w.Body.String())
	}
}

func TestStaticHandlerFallbackForSPARoute(t *testing.T) {
	// /audit/abc123 — a React-router path with no on-disk asset.
	h := StaticHandler(newTestFS())
	req := httptest.NewRequest(http.MethodGet, "/audit/abc123", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("SPA fallback status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "SPA") {
		t.Errorf("SPA fallback did not serve index.html: %q", w.Body.String())
	}
}

func TestStaticHandlerRefusesAPIPaths(t *testing.T) {
	h := StaticHandler(newTestFS())
	for _, p := range []string{"/api/audits", "/health", "/metrics", "/debug/pprof"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("API path %q status = %d, want 404 (static handler must not mask API)", p, w.Code)
		}
		if strings.Contains(w.Body.String(), "SPA") {
			t.Errorf("API path %q served SPA fallback; that masks the real API route", p)
		}
	}
}

func TestStaticHandlerRejectsNonGET(t *testing.T) {
	h := StaticHandler(newTestFS())
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(m, "/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s / status = %d, want 405", m, w.Code)
		}
	}
}

func TestStaticHandlerSetsSecurityHeaders(t *testing.T) {
	h := StaticHandler(newTestFS())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	wantHeaders := map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Permissions-Policy":      "geolocation",
	}
	for k, wantSubstr := range wantHeaders {
		got := w.Header().Get(k)
		if !strings.Contains(got, wantSubstr) {
			t.Errorf("header %s = %q, want substring %q", k, got, wantSubstr)
		}
	}

	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'self'",
		"frame-ancestors 'none'",
		"connect-src 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing directive %q (got %q)", want, csp)
		}
	}
}

func TestStaticHandlerNoSPAFallbackWhenIndexMissing(t *testing.T) {
	// FS without index.html — fallback should 404 rather than crash.
	h := StaticHandler(fstest.MapFS{
		"assets/app.js": &fstest.MapFile{Data: []byte("x")},
	})
	req := httptest.NewRequest(http.MethodGet, "/audit/abc", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when index.html is absent", w.Code)
	}
}
