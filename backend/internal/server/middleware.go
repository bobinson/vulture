package server

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
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
		// 0065 F5: quote the request-controlled path so an embedded CR/LF
		// cannot forge an additional log record. r.Method is RFC-token
		// validated by net/http and cannot carry CR/LF.
		log.Printf("method=%s path=%s status=%d duration=%s remote=%s",
			r.Method, strconv.Quote(r.URL.Path), sw.code, time.Since(start), r.RemoteAddr)
	})
}

func isStreamPath(path string) bool {
	return strings.HasSuffix(path, "/stream")
}

// 0065 F2 — trusted-proxy client IP.
//
// trustedProxyNets holds the CIDRs/hosts configured via
// VULTURE_TRUSTED_PROXIES. X-Forwarded-For is honored only when the direct
// peer is one of these; otherwise an untrusted peer cannot spoof its own IP.
var trustedProxyNets []*net.IPNet

// ConfigureTrustedProxies parses trusted-proxy entries (IPs or CIDRs) and
// installs them for realClientIP. Called once at startup.
func ConfigureTrustedProxies(entries []string) error {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			return fmt.Errorf("invalid trusted proxy %q", e)
		}
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	trustedProxyNets = nets
	return nil
}

func isTrustedProxy(ip net.IP) bool {
	for _, n := range trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// realClientIP: XFF honored only when the direct peer is a trusted proxy, and
// then the rightmost non-trusted hop wins; otherwise the peer wins and XFF is
// ignored (an untrusted peer cannot spoof its own IP).
func realClientIP(r *http.Request) string {
	peer := hostOnly(r.RemoteAddr)
	if pip := net.ParseIP(peer); pip == nil || !isTrustedProxy(pip) {
		return peer
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		if h := strings.TrimSpace(parts[i]); h != "" {
			if ip := net.ParseIP(h); ip != nil && !isTrustedProxy(ip) {
				return h
			}
		}
	}
	return peer
}

func hostOnly(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
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
		if !rl.allow(realClientIP(r)) {
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

// clientIP extracts the client IP, honoring X-Forwarded-For only from a
// trusted proxy (delegates to realClientIP — 0065 F2).
func clientIP(r *http.Request) string {
	return realClientIP(r)
}

// 0065 F6/H2/H3/R5 — bounded, oracle-free login throttle.
//
// Keyed on (email, client-IP): an attacker cannot lock out a victim globally,
// only from their own IP. Uses an escalating delay rather than a hard lock (no
// distinct "locked" status ⇒ no enumeration oracle, §H2) and a swept, bounded
// map (§H3).
type LoginThrottle struct {
	mu        sync.Mutex
	fails     map[string]*failRec
	max       int
	window    time.Duration
	lastEvict time.Time
}

type failRec struct {
	count int
	first time.Time
}

func NewLoginThrottle(max int, window time.Duration) *LoginThrottle {
	return &LoginThrottle{fails: map[string]*failRec{}, max: max, window: window}
}

func lkey(email, ip string) string {
	return strings.ToLower(strings.TrimSpace(email)) + "|" + ip
}

// Delay returns how long to stall before this (email,ip) may attempt. 0 under
// the threshold; grows 1s per over-limit failure, capped at 5s. Same generic
// response either way (caller stalls then returns invalid-credentials) so no
// lock state leaks (§H2). Returns -1 past the hard ceiling (§R5) so the caller
// answers 429 without parking a goroutine.
func (t *LoginThrottle) Delay(email, ip string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.maybeEvict(time.Now())
	r := t.fails[lkey(email, ip)]
	if r == nil || time.Since(r.first) > t.window || r.count < t.max {
		return 0
	}
	if r.count >= 2*t.max {
		return -1 // §R5 hard ceiling: caller returns 429 without sleeping
	}
	d := time.Duration(r.count-t.max+1) * time.Second
	if d > 5*time.Second {
		d = 5 * time.Second // maxSleep
	}
	return d
}

func (t *LoginThrottle) Fail(email, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k, now := lkey(email, ip), time.Now()
	if r := t.fails[k]; r != nil && time.Since(r.first) <= t.window {
		r.count++
		return
	}
	t.fails[k] = &failRec{count: 1, first: now}
}

func (t *LoginThrottle) Reset(email, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.fails, lkey(email, ip))
}

// maybeEvict sweeps expired records at most once per window when large (§H3,
// same amortization as the request rate limiter). Caller holds the lock.
func (t *LoginThrottle) maybeEvict(now time.Time) {
	if len(t.fails) <= 1000 || now.Sub(t.lastEvict) < t.window {
		return
	}
	for k, r := range t.fails {
		if now.Sub(r.first) > t.window {
			delete(t.fails, k)
		}
	}
	t.lastEvict = now
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
