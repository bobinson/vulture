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

func addCORS(next http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Security headers (ISO 26262 compliance)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// CORS
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization")
		w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
	return mux
}

func isStreamPath(path string) bool {
	return strings.HasSuffix(path, "/stream")
}

// rateLimiter implements a simple per-IP token bucket rate limiter.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    int
	window  time.Duration
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

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Evict stale buckets to prevent unbounded memory growth
	if len(rl.buckets) > 1000 {
		for k, v := range rl.buckets {
			if now.Sub(v.lastReset) > rl.window {
				delete(rl.buckets, k)
			}
		}
	}

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
