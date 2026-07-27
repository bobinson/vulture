package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/handler"
	"github.com/vulture/backend/internal/model"
)

// 0065 §3.4 (M11) — httptest-level E2E through the real mux + middleware for the
// auth-surface hardening: (1) a rotating X-Forwarded-For cannot defeat the login
// rate limiter, (2) a CRLF path cannot forge a log record, (3) the login throttle
// keys per (email, IP).

// fakeAuthService always fails Login so the E2E can exercise the throttle path
// without a real user store.
type fakeAuthService struct{}

func (fakeAuthService) Register(*model.RegisterRequest) (*model.AuthResponse, error) {
	return nil, fmt.Errorf("invalid credentials")
}
func (fakeAuthService) Login(*model.LoginRequest) (*model.AuthResponse, error) {
	return nil, fmt.Errorf("invalid credentials")
}
func (fakeAuthService) ValidateToken(string) (*model.User, error) {
	return nil, fmt.Errorf("invalid token")
}
func (fakeAuthService) ValidateLocalUser() (*model.User, error) {
	return nil, fmt.Errorf("no local user")
}
func (fakeAuthService) IssueLocalAdminToken() (*model.AuthResponse, error) {
	return nil, fmt.Errorf("no local admin")
}

// TestE2E_RotatingXFFCannotDefeatLoginLimiter drives the real RateLimit
// middleware through a mux: with no trusted proxies configured, a peer that
// rotates X-Forwarded-For on every request must still be bucketed on its own
// (peer) IP and get rate-limited.
func TestE2E_RotatingXFFCannotDefeatLoginLimiter(t *testing.T) {
	if err := ConfigureTrustedProxies(nil); err != nil {
		t.Fatalf("ConfigureTrustedProxies: %v", err)
	}
	t.Cleanup(func() { _ = ConfigureTrustedProxies(nil) })

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", RateLimit(3, time.Minute, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	const peer = "203.0.113.9:1234"
	do := func(xff string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
		req.RemoteAddr = peer
		req.Header.Set("X-Forwarded-For", xff)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr.Code
	}

	for i := 0; i < 3; i++ {
		if code := do(fmt.Sprintf("10.0.0.%d", i)); code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, code)
		}
	}
	// 4th request from same peer, brand-new spoofed XFF — must be limited.
	if code := do("10.9.9.9"); code != http.StatusTooManyRequests {
		t.Fatalf("rotated-XFF 4th request: got %d, want 429 (bucket keys on peer, not XFF)", code)
	}
}

// TestE2E_CRLFPathDoesNotForgeLogRecord drives the real addRequestLogging
// middleware through the mux and asserts a CR/LF in the path is emitted quoted
// on a single line.
func TestE2E_CRLFPathDoesNotForgeLogRecord(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	const evil = "/api/x\nmethod=GET path=/admin status=200"
	h := addRequestLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.URL.Path = evil
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	if strings.Contains(strings.TrimRight(out, "\n"), "\n") {
		t.Fatalf("log output contains an embedded newline (forged record):\n%q", out)
	}
	if !strings.Contains(out, strconv.Quote(evil)) {
		t.Fatalf("log output does not contain quoted path %q; got:\n%q", strconv.Quote(evil), out)
	}
}

// TestE2E_LoginThrottlePerEmailIP drives the real AuthHandler + LoginThrottle +
// RateLimit through the mux. Past the hard ceiling the (email,peer) combo is
// rejected 429 without sleeping, while the same email from a different IP is
// unaffected (401 invalid-credentials).
func TestE2E_LoginThrottlePerEmailIP(t *testing.T) {
	if err := ConfigureTrustedProxies(nil); err != nil {
		t.Fatalf("ConfigureTrustedProxies: %v", err)
	}
	t.Cleanup(func() { _ = ConfigureTrustedProxies(nil) })

	authH := handler.NewAuthHandler(fakeAuthService{})
	throttle := NewLoginThrottle(3, time.Minute)
	authH.SetLoginThrottle(throttle, realClientIP)

	// RateLimit generous so it never fires within this test; throttle is the
	// mechanism under test.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", RateLimit(1000, time.Minute, authH.Login))

	const email = "victim@example.com"
	const attackerIP = "10.0.0.5"

	// Pre-drive the throttle past the hard ceiling (2*max = 6) for (email, attackerIP)
	// directly, so we don't have to sleep through escalating delays.
	for i := 0; i < 6; i++ {
		throttle.Fail(email, attackerIP)
	}

	body, _ := json.Marshal(model.LoginRequest{Email: email, Password: "x"})
	call := func(remoteAddr string) (int, time.Duration) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.RemoteAddr = remoteAddr
		rr := httptest.NewRecorder()
		start := time.Now()
		mux.ServeHTTP(rr, req)
		return rr.Code, time.Since(start)
	}

	// Attacker IP past the ceiling: 429 immediately (no goroutine parking / sleep).
	code, elapsed := call(attackerIP + ":40000")
	if code != http.StatusTooManyRequests {
		t.Fatalf("attacker IP past ceiling: got %d, want 429", code)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("attacker IP request slept %v; hard ceiling must reject without sleeping", elapsed)
	}

	// Same email, different IP: throttle not engaged -> normal 401 invalid credentials.
	code, _ = call("192.168.1.1:40000")
	if code != http.StatusUnauthorized {
		t.Fatalf("victim from a different IP: got %d, want 401 (no cross-IP lockout)", code)
	}
}
