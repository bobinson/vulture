package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

// 0036 Phase 4 — the historical weak local-dev default is rejected by
// SHA-256 hash, not by literal, so the string can be scrubbed from git
// history. The preimage is assembled by concatenation here so the
// contiguous literal never reappears in source (which would defeat the
// scrub). This test also validates knownWeakDevPasswordHash is correct.
func TestResolveLocalDevPassword_RejectsKnownWeakDefault(t *testing.T) {
	weak := "vulture" + "2024"
	t.Setenv("VULTURE_LOCAL_DEV_PASSWORD", weak)
	if _, _, err := resolveLocalDevPassword(); err == nil {
		t.Fatal("expected the known-weak historical default to be rejected")
	}
}

func TestResolveLocalDevPassword_AcceptsStrongValue(t *testing.T) {
	const strong = "a-strong-unique-dev-password-9173"
	t.Setenv("VULTURE_LOCAL_DEV_PASSWORD", strong)
	pw, generated, err := resolveLocalDevPassword()
	if err != nil {
		t.Fatalf("unexpected error for strong value: %v", err)
	}
	if generated {
		t.Error("password should not be CSPRNG-generated when env is set")
	}
	if pw != strong {
		t.Errorf("got %q, want the provided strong value", pw)
	}
}

// 0036 Phase 3 (M9) — JWT secret minimum length.
// HS256 requires a 32-byte key per RFC 7518 §3.2. Short secrets are
// brute-forceable; refuse to start.
func TestJWTSecretMinLength(t *testing.T) {
	cases := []struct {
		name      string
		secret    string
		localMode bool
		wantErr   bool
	}{
		{"empty + local → ok", "", true, false},
		{"short + local → ok (local mode bypasses)", "short", true, false},
		{"empty + non-local → REFUSE", "", false, true},
		{"31 chars + non-local → REFUSE", strings.Repeat("a", 31), false, true},
		{"32 chars + non-local → ok", strings.Repeat("a", 32), false, false},
		{"64 chars + non-local → ok", strings.Repeat("a", 64), false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateJWTSecret(c.secret, c.localMode)
			if c.wantErr && err == nil {
				t.Errorf("expected error; got nil")
			}
			if !c.wantErr && err != nil {
				t.Errorf("expected nil; got %v", err)
			}
		})
	}
}

// 0036 Phase 3 — agent-token startup gate (T12).
// Mode B without VULTURE_AGENT_TOKEN means agents accept credentialless
// HTTP. Refuse to start the backend in that configuration.
func TestValidateAgentTokenForNonLocalMode(t *testing.T) {
	cases := []struct {
		name      string
		token     string
		localMode bool
		wantErr   bool
	}{
		{"local mode, no token → ok", "", true, false},
		{"local mode, token set → ok", "secret", true, false},
		{"non-local, no token → REFUSE", "", false, true},
		{"non-local, token set → ok", "secret", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateAgentTokenForNonLocalMode(c.token, c.localMode)
			if c.wantErr && err == nil {
				t.Errorf("expected error; got nil")
			}
			if !c.wantErr && err != nil {
				t.Errorf("expected nil; got %v", err)
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
