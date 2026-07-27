package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsStreamPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/api/audits/abc/stream", true},
		{"/api/audits/abc", false},
		{"/api/audits/", false},
		{"/stream", true},
	}
	for _, tc := range tests {
		got := isStreamPath(tc.path)
		if got != tc.want {
			t.Errorf("isStreamPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// staticKeyFunc returns a keyFunc that always returns the given key.
func staticKeyFunc(key string) func(*http.Request) string {
	return func(*http.Request) string { return key }
}

func TestRateLimitByKey_AllowsWithinLimit(t *testing.T) {
	called := 0
	handler := RateLimitByKey(5, staticKeyFunc("user1"), func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/audits", nil)
		handler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got status %d, want 200", i+1, rr.Code)
		}
	}
	if called != 5 {
		t.Fatalf("handler called %d times, want 5", called)
	}
}

func TestRateLimitByKey_BlocksOverLimit(t *testing.T) {
	handler := RateLimitByKey(3, staticKeyFunc("user1"), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Exhaust the 3-request limit
	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/audits", nil)
		handler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got status %d, want 200", i+1, rr.Code)
		}
	}

	// 4th request should be rejected
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/audits", nil)
	handler(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("request 4: got status %d, want 429", rr.Code)
	}
}

func TestRateLimitByKey_DifferentKeysIndependent(t *testing.T) {
	// Use a counter per key to vary the keyFunc response via Authorization header.
	keyFunc := func(r *http.Request) string {
		return r.Header.Get("X-Test-Key")
	}
	handler := RateLimitByKey(2, keyFunc, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Exhaust limit for key "A"
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/audits", nil)
		req.Header.Set("X-Test-Key", "A")
		handler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("key=A request %d: got %d, want 200", i+1, rr.Code)
		}
	}

	// Key "A" should now be blocked
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/audits", nil)
	req.Header.Set("X-Test-Key", "A")
	handler(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("key=A request 3: got %d, want 429", rr.Code)
	}

	// Key "B" should still be allowed (independent bucket)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/audits", nil)
	req.Header.Set("X-Test-Key", "B")
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("key=B request 1: got %d, want 200", rr.Code)
	}
}

// --- 0065 §3.1 F2: trusted-proxy client IP (RED baseline) ---

// TestRateLimit_XFFDoesNotResetPerIPBucket asserts the secure default: with no
// trusted proxies configured an untrusted peer cannot spoof its client IP via
// X-Forwarded-For, so a rotating XFF must NOT mint a fresh rate-limit bucket.
// The limiter must key on the direct peer (RemoteAddr host).
//
// Current code keys on the first XFF entry, so every rotated XFF is a new bucket
// and the peer is never limited -> the 4th request returns 200, FAILING this test.
func TestRateLimit_XFFDoesNotResetPerIPBucket(t *testing.T) {
	handler := RateLimit(3, time.Minute, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	const peer = "203.0.113.9:1234"

	// Exhaust the 3-request budget from one peer, each with a different XFF.
	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
		req.RemoteAddr = peer
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i))
		handler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, rr.Code)
		}
	}

	// 4th request: same peer, brand-new spoofed XFF. Must be rate-limited because
	// the bucket keys on the peer, not the attacker-controlled XFF.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = peer
	req.Header.Set("X-Forwarded-For", "10.9.9.9")
	handler(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request with rotated XFF: got %d, want 429 (bucket must key on peer, not XFF)", rr.Code)
	}
}

// --- 0065 §3.1 F6/H2/H3/R5: bounded, oracle-free login throttle (RED baseline) ---

// TestLoginThrottle_DelayEngagesAtThreshold: below the threshold Delay is 0; once
// failures reach max the (max+1)th attempt is stalled (Delay > 0).
func TestLoginThrottle_DelayEngagesAtThreshold(t *testing.T) {
	thr := NewLoginThrottle(3, time.Minute)
	const email, ip = "user@example.com", "203.0.113.9"

	thr.Fail(email, ip)
	thr.Fail(email, ip)
	if d := thr.Delay(email, ip); d != 0 {
		t.Fatalf("below threshold: Delay = %v, want 0", d)
	}

	thr.Fail(email, ip) // reaches max
	if d := thr.Delay(email, ip); d <= 0 {
		t.Fatalf("at threshold: Delay = %v, want > 0 (throttle engaged)", d)
	}
}

// TestLoginThrottle_VictimDifferentIPUnaffected (§H2): throttling is keyed on
// (email, IP), so an attacker hammering an account from one IP cannot lock the
// victim out from a different IP.
func TestLoginThrottle_VictimDifferentIPUnaffected(t *testing.T) {
	thr := NewLoginThrottle(3, time.Minute)
	const email = "victim@example.com"

	for i := 0; i < 5; i++ {
		thr.Fail(email, "10.0.0.9") // attacker IP
	}

	if d := thr.Delay(email, "192.168.1.1"); d != 0 {
		t.Fatalf("victim from a different IP: Delay = %v, want 0 (no cross-IP lockout)", d)
	}
	if d := thr.Delay(email, "10.0.0.9"); d <= 0 {
		t.Fatalf("attacker IP: Delay = %v, want > 0", d)
	}
}

// TestLoginThrottle_HardCeilingRejects (§R5): past a hard ceiling (2*max) Delay
// returns a negative sentinel so the handler answers 429 immediately instead of
// parking a goroutine in time.Sleep.
func TestLoginThrottle_HardCeilingRejects(t *testing.T) {
	thr := NewLoginThrottle(3, time.Minute)
	const email, ip = "user@example.com", "203.0.113.9"

	for i := 0; i < 6; i++ { // 2*max
		thr.Fail(email, ip)
	}
	if d := thr.Delay(email, ip); d >= 0 {
		t.Fatalf("at hard ceiling: Delay = %v, want < 0 (immediate 429, no goroutine parking)", d)
	}
}

// TestLoginThrottle_EvictsExpired (§H3): the fails map is swept so a distinct-key
// flood cannot grow it without bound. Expired records are removed by maybeEvict.
func TestLoginThrottle_EvictsExpired(t *testing.T) {
	thr := NewLoginThrottle(3, 50*time.Millisecond)
	old := time.Now().Add(-time.Hour)
	for i := 0; i < 1001; i++ {
		thr.fails[fmt.Sprintf("stale-%d", i)] = &failRec{count: 1, first: old}
	}

	thr.maybeEvict(time.Now())

	if len(thr.fails) != 0 {
		t.Fatalf("maybeEvict left %d stale records, want 0", len(thr.fails))
	}
}

func TestRateLimitByKey_FallsBackToIPWhenNoUser(t *testing.T) {
	// keyFunc returns "" to simulate no authenticated user
	handler := RateLimitByKey(2, staticKeyFunc(""), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First 2 requests from same IP succeed
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/audits", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		handler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, rr.Code)
		}
	}

	// 3rd request from same IP is blocked
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/audits", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	handler(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("request 3 same IP: got %d, want 429", rr.Code)
	}

	// Request from a different IP succeeds (separate bucket)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/audits", nil)
	req.RemoteAddr = "10.0.0.2:12345"
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("request from different IP: got %d, want 200", rr.Code)
	}
}
