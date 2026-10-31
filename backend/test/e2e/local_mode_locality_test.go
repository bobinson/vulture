//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/config"
)

// Local mode is passwordless: a request without a token is served as the local
// user, /api/auth/local-session mints a token for anyone who asks, and open
// registration is on. That is only safe for requests made on this machine. A
// reverse proxy on the same host — the dev frontend's Vite proxy, which
// listened on every interface — connects from loopback on behalf of whoever
// reached it, so a loopback peer alone proves nothing. These tests pin the
// business rule: local mode serves a request only when it is local END TO END.

// localityCase is one request shape the dev stack can receive.
type localityCase struct {
	name   string
	method string
	path   string
	host   string            // Host header override; "" keeps the dialled address
	header map[string]string // forwarding headers a proxy (or a client) sets
	body   string
}

// localModeConfig is testConfig with the registration default config.Load
// derives for local mode (open registration on), so the register cases test
// the locality rule rather than an admin-only route.
func localModeConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := testConfig(t)
	cfg.AllowOpenRegistration = true
	return cfg
}

func doLocality(t *testing.T, addr string, c localityCase) int {
	t.Helper()
	req, err := http.NewRequest(c.method, "http://"+addr+c.path, strings.NewReader(c.body))
	if err != nil {
		t.Fatalf("%s: build request: %v", c.name, err)
	}
	if c.host != "" {
		req.Host = c.host
	}
	if c.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range c.header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", c.name, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestLocalMode_ServesRequestsFromThisMachine: the local user's own requests —
// direct, or relayed by the dev proxy for a browser on this machine — keep the
// passwordless experience.
func TestLocalMode_ServesRequestsFromThisMachine(t *testing.T) {
	addr, cleanup := startTestServer(t, localModeConfig(t))
	defer cleanup()

	for _, c := range []localityCase{
		{name: "direct, no token", method: http.MethodGet, path: "/api/audits"},
		{name: "dev proxy relaying a local IPv4 browser", method: http.MethodGet, path: "/api/audits",
			host: "localhost:23001", header: map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{name: "dev proxy relaying a local IPv6 browser", method: http.MethodGet, path: "/api/audits",
			host: "[::1]:23001", header: map[string]string{"X-Forwarded-For": "::1"}},
		{name: "local session for the local user", method: http.MethodGet, path: "/api/auth/local-session"},
	} {
		if got := doLocality(t, addr, c); got != http.StatusOK {
			t.Errorf("%s: status %d, want 200", c.name, got)
		}
	}

	register := localityCase{name: "local user registering an account", method: http.MethodPost,
		path: "/api/auth/register", body: `{"email":"local@example.test","password":"correct-horse-battery-staple","name":"Local"}`}
	if got := doLocality(t, addr, register); got != http.StatusCreated {
		t.Errorf("%s: status %d, want 201", register.name, got)
	}
}

// TestLocalMode_RefusesRequestsFromAnotherMachine: anything relayed for a
// client elsewhere, or addressed to a non-loopback name (DNS rebinding), gets
// nothing — not the token-less identity, not a session, not an account.
func TestLocalMode_RefusesRequestsFromAnotherMachine(t *testing.T) {
	addr, cleanup := startTestServer(t, localModeConfig(t))
	defer cleanup()

	lan := "192.168.68.50"
	for _, c := range []localityCase{
		{name: "proxy relaying a LAN client", method: http.MethodGet, path: "/api/audits",
			header: map[string]string{"X-Forwarded-For": lan}},
		{name: "LAN client prefixing a forged loopback hop", method: http.MethodGet, path: "/api/audits",
			header: map[string]string{"X-Forwarded-For": "127.0.0.1, " + lan}},
		{name: "proxy using X-Real-IP", method: http.MethodGet, path: "/api/audits",
			header: map[string]string{"X-Real-IP": lan}},
		{name: "proxy using RFC 7239 Forwarded", method: http.MethodGet, path: "/api/audits",
			header: map[string]string{"Forwarded": "for=" + lan + ";proto=http"}},
		{name: "proxy recording an unknown client", method: http.MethodGet, path: "/api/audits",
			header: map[string]string{"Forwarded": "for=unknown"}},
		{name: "LAN client asking for a local session", method: http.MethodGet, path: "/api/auth/local-session",
			header: map[string]string{"X-Forwarded-For": lan}},
		{name: "LAN client spoofing Host: localhost for a session", method: http.MethodGet,
			path: "/api/auth/local-session", host: "localhost:23001",
			header: map[string]string{"X-Forwarded-For": lan}},
		{name: "LAN client registering an account", method: http.MethodPost, path: "/api/auth/register",
			header: map[string]string{"X-Forwarded-For": lan},
			body:   `{"email":"lan@example.test","password":"correct-horse-battery-staple","name":"LAN"}`},
		{name: "DNS-rebinding page in the local browser", method: http.MethodGet, path: "/api/audits",
			host: "rebind.example:28080"},
		{name: "health is not an exception", method: http.MethodGet, path: "/health",
			header: map[string]string{"X-Forwarded-For": lan}},
	} {
		if got := doLocality(t, addr, c); got != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", c.name, got)
		}
	}
}
