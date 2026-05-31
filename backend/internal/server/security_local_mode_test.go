package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 0036 Phase 3 — security hardening for Mode B.
// Pins the contract for findings C3, H7, H9 from the 2026-04-25 audit.
// C1 (admin-seed gating) is enforced at the server.go:283 call site
// (`if userRepo != nil && cfg.LocalMode { seedLocalUser(...) }`) and
// is exercised by the existing auth E2E tests.

// H9 — VULTURE_LOCAL_MODE refuses to bind on non-loopback addresses.
// Without this check, a Mode-A install accidentally exposed via
// VULTURE_LOCAL_MODE=true was a public-internet admin backdoor.
func TestLocalModeRefusesNonLoopbackBind(t *testing.T) {
	cases := []struct {
		addr      string
		localMode bool
		wantErr   bool
	}{
		{":28080", true, true},
		{"0.0.0.0:28080", true, true},
		{"192.168.1.10:28080", true, true},
		{"[::]:28080", true, true},
		{"127.0.0.1:28080", true, false},
		{"localhost:28080", true, false},
		{"[::1]:28080", true, false},
		{":28080", false, false},
		{"0.0.0.0:28080", false, false},
	}
	for _, c := range cases {
		t.Run(c.addr, func(t *testing.T) {
			err := validateLoopbackForLocalMode(c.addr, c.localMode)
			if c.wantErr && err == nil {
				t.Errorf("validateLoopbackForLocalMode(%q, %v) = nil; want error",
					c.addr, c.localMode)
			}
			if !c.wantErr && err != nil {
				t.Errorf("validateLoopbackForLocalMode(%q, %v) = %v; want nil",
					c.addr, c.localMode, err)
			}
		})
	}
}

// Cross-check on the underlying parse: an addr string must split into
// a host and a port. The empty-host case (":port") means
// "bind all interfaces", which is non-loopback per H9.
func TestIsLoopbackBind(t *testing.T) {
	loopback := []string{
		"127.0.0.1:28080",
		"[::1]:28080",
		"localhost:28080",
	}
	notLoopback := []string{
		":28080",
		"0.0.0.0:28080",
		"[::]:28080",
		"192.168.1.10:28080",
		"10.0.0.1:28080",
	}
	for _, a := range loopback {
		if !isLoopbackBind(a) {
			t.Errorf("isLoopbackBind(%q) = false; want true", a)
		}
	}
	for _, a := range notLoopback {
		if isLoopbackBind(a) {
			t.Errorf("isLoopbackBind(%q) = true; want false", a)
		}
	}
}

// C3 — CORS must never return `Access-Control-Allow-Origin: *` together
// with `Access-Control-Allow-Credentials: true`. The combination is
// rejected by browsers but the headers are still served, leaking
// origin-permissive intent. With an allowlist only matching origins
// are echoed back.
func TestCORSAllowlistBehavior(t *testing.T) {
	tests := []struct {
		name         string
		allowlist    []string
		reqOrigin    string
		wantOrigin   string
		wantNoOrigin bool
	}{
		{
			name:         "empty allowlist + unknown origin → no header",
			allowlist:    nil,
			reqOrigin:    "https://attacker.example",
			wantNoOrigin: true,
		},
		{
			name:       "matching origin → echoed back, no wildcard",
			allowlist:  []string{"https://app.example.com"},
			reqOrigin:  "https://app.example.com",
			wantOrigin: "https://app.example.com",
		},
		{
			name:         "non-matching origin → no header",
			allowlist:    []string{"https://app.example.com"},
			reqOrigin:    "https://evil.example",
			wantNoOrigin: true,
		},
		{
			name:       "empty allowlist + no Origin header → no error",
			allowlist:  nil,
			reqOrigin:  "",
			wantNoOrigin: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})
			mux := addCORSWithAllowlist(next, tc.allowlist)
			req := httptest.NewRequest(http.MethodOptions, "/api/audits", nil)
			if tc.reqOrigin != "" {
				req.Header.Set("Origin", tc.reqOrigin)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			gotOrigin := rec.Header().Get("Access-Control-Allow-Origin")
			gotCreds := rec.Header().Get("Access-Control-Allow-Credentials")

			if gotOrigin == "*" && gotCreds == "true" {
				t.Errorf("CORS returned wildcard origin with credentials=true — forbidden combo")
			}
			if tc.wantNoOrigin && gotOrigin != "" {
				t.Errorf("expected no Allow-Origin header; got %q", gotOrigin)
			}
			if tc.wantOrigin != "" && gotOrigin != tc.wantOrigin {
				t.Errorf("expected Allow-Origin=%q; got %q", tc.wantOrigin, gotOrigin)
			}
		})
	}
}

// H7 — LocalSession returns a passwordless admin token. Even with the
// local-mode flag gating, an attacker who reaches the endpoint over a
// non-loopback Host header gets the credential. H9 makes this redundant
// in normal deployments, but defence-in-depth requires the handler
// itself to reject non-loopback Host.
func TestIsLoopbackHost(t *testing.T) {
	loopback := []string{
		"localhost",
		"localhost:28080",
		"127.0.0.1",
		"127.0.0.1:28080",
		"[::1]",
		"[::1]:28080",
		"",
	}
	notLoopback := []string{
		"evil.example",
		"some.real.domain.com",
		"localhost.attacker.com",
		"127.0.0.1.attacker.com",
		"192.168.1.10",
		"192.168.1.10:8080",
	}
	for _, h := range loopback {
		if !isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = false; want true", h)
		}
	}
	for _, h := range notLoopback {
		if isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = true; want false", h)
		}
	}
}
