package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
