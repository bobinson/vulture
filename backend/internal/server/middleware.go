package server

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// statusWriter captures the HTTP status code written by the handler.
// It also implements http.Flusher so SSE streaming works through the logging middleware.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.code = code
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func addRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Printf("method=%s path=%s status=%d duration=%s remote=%s",
			r.Method, r.URL.Path, sw.code, time.Since(start), r.RemoteAddr)
	})
}

func isStreamPath(path string) bool {
	return strings.HasSuffix(path, "/stream")
}

// rateLimiter implements a simple per-IP token bucket rate limiter.
type rateLimiter struct {
	mu           sync.Mutex
	buckets      map[string]*bucket
	rate         int
	window       time.Duration
	lastEviction time.Time
}

type bucket struct {
	tokens    int
	lastReset time.Time
}

func newRateLimiter(rate int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		window:  window,
	}
}

// allow holds rl.mu only briefly per request: the eviction sweep that
// previously ran on every call once len(buckets) > 1000 is now amortized
// to at most once per window. Most requests pay only O(1) map ops.
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	rl.maybeEvict(now)

	b, ok := rl.buckets[ip]
	if !ok || now.Sub(b.lastReset) > rl.window {
		rl.buckets[ip] = &bucket{tokens: rl.rate - 1, lastReset: now}
		return true
	}

	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// maybeEvict runs a stale-bucket sweep at most once per window when the
// map is large. Caller must hold rl.mu. Even when triggered, the sweep is
// bounded: with N active buckets and a sweep cadence of `window`, the
// amortized per-request cost is O(1).
func (rl *rateLimiter) maybeEvict(now time.Time) {
	if len(rl.buckets) <= 1000 {
		return
	}
	if now.Sub(rl.lastEviction) < rl.window {
		return
	}
	for k, v := range rl.buckets {
		if now.Sub(v.lastReset) > rl.window {
			delete(rl.buckets, k)
		}
	}
	rl.lastEviction = now
}

// RateLimit wraps a handler with rate limiting per IP.
func RateLimit(limit int, window time.Duration, next http.HandlerFunc) http.HandlerFunc {
	rl := newRateLimiter(limit, window)
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			ip = strings.Split(fwd, ",")[0]
		}
		if !rl.allow(strings.TrimSpace(ip)) {
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// RateLimitByKey limits requests by the authenticated principal (API key or user ID).
// keyFunc extracts the rate-limit key from the request; if it returns "" the
// middleware falls back to IP-based limiting.
func RateLimitByKey(rpm int, keyFunc func(*http.Request) string, next http.HandlerFunc) http.HandlerFunc {
	rl := newRateLimiter(rpm, time.Minute)
	return func(w http.ResponseWriter, r *http.Request) {
		key := keyFunc(r)
		if key == "" {
			key = clientIP(r)
		}
		if !rl.allow(key) {
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// clientIP extracts the client IP, preferring X-Forwarded-For when present.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	return r.RemoteAddr
}

// principalKeyFunc returns a key-extraction function that derives the
// rate-limit key from the Authorization header. API key tokens (vk_ prefix)
// use the token itself; other Bearer tokens use "jwt:<token-prefix>" to
// provide a stable per-user key without needing access to the decoded JWT.
// Returns "" when no Authorization header is present (triggers IP fallback).
func principalKeyFunc(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	token := strings.TrimPrefix(h, "Bearer ")
	if token == h {
		return "" // not a Bearer token
	}
	if strings.HasPrefix(token, "vk_") {
		return "apikey:" + token
	}
	// JWT tokens: use the full token as key (stable per session).
	return "jwt:" + token
}
