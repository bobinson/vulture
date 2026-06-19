package handler

import (
	"io/fs"
	"net/http"
	"regexp"
	"strings"
)

// SPAFallbackExclusionRE matches paths that must NOT fall back to
// index.html. API routes need to return real 404s so callers can
// distinguish "endpoint does not exist" from "the SPA is loading".
// See plan invariant S6.
var SPAFallbackExclusionRE = regexp.MustCompile(`^/(api|health|metrics|debug)(/|$)`)

// IsAPIPath reports whether p belongs to the API surface and should
// NOT be masked by the SPA history-API fallback. Exported for tests
// and for direct use by callers that need to short-circuit the
// fallback themselves.
func IsAPIPath(p string) bool {
	return SPAFallbackExclusionRE.MatchString(p)
}

// StaticHandler returns an http.Handler that serves the SPA from
// staticFS with a history-API fallback (any non-API path that does
// not resolve to a real file gets index.html). Every response is
// wrapped in a security-headers middleware (CSP, frame-ancestors
// 'none', etc.) — see invariant S14.
//
// The handler is intentionally restricted to GET / HEAD. Any other
// method returns 405. CORS in install mode is locked to the loopback
// origin and is applied by the caller's middleware chain.
func StaticHandler(staticFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(staticFS))
	return securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Never fall back for API paths: let the real router answer.
		if IsAPIPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		// Try the asset directly.
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(staticFS, path); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}
		// SPA history fallback: serve index.html so the React router
		// can take over.
		serveIndex(w, r, staticFS)
	}))
}

func serveIndex(w http.ResponseWriter, r *http.Request, staticFS fs.FS) {
	data, err := fs.ReadFile(staticFS, "index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

// securityHeadersMiddleware injects the headers required by invariant
// S14. Applied unconditionally to every response from the static
// handler.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				// Google Fonts: the SPA links fonts.googleapis.com (CSS) which
				// pulls font files from fonts.gstatic.com. Without these the CSP
				// blocked the stylesheet (console error; fonts fell back). 0055.
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		next.ServeHTTP(w, r)
	})
}
