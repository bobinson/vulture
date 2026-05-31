package server

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// 0036 Phase 3 — Mode-B security hardening.
//
// This file collects the small helpers introduced to close the
// 2026-04-25 audit's critical / high Mode-B findings:
//
//   * C3 — wildcard CORS: addCORSWithAllowlist drives
//     Access-Control-Allow-Origin from an explicit allowlist; never
//     emits "*" alongside Allow-Credentials: true.
//   * H7 — local-session host check: isLoopbackHost lets the auth
//     handler reject non-loopback Host headers as defence-in-depth.
//   * H9 — non-loopback bind in local mode:
//     validateLoopbackForLocalMode refuses to start with a non-loopback
//     listen address when VULTURE_LOCAL_MODE=true.
//
// C1 (admin seed gated to local mode) is enforced at the call site in
// server.go::setupAuth and has no helper here.

// isLoopbackBind reports whether `addr` (a "host:port" listen string)
// binds to a loopback interface only. Empty host (":port") means
// "all interfaces" and is treated as non-loopback.
func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Bare addresses with no port aren't valid listen strings;
		// be conservative and reject as non-loopback.
		return false
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return false
	}
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// validateAgentTokenForNonLocalMode refuses startup when LocalMode is
// off AND no agent token is configured. The Python agent services
// reject untokened requests when VULTURE_AGENT_TOKEN is set; this
// check ensures an operator can't accidentally deploy Mode B with
// credentialless agent access.
//
// 0036 Phase 3 — agent-token-required-in-non-local-mode.
func validateAgentTokenForNonLocalMode(token string, localMode bool) error {
	if localMode {
		return nil
	}
	if token == "" {
		return fmt.Errorf(
			"VULTURE_AGENT_TOKEN is required when not in local mode " +
				"(otherwise agent services would accept credential-less HTTP). " +
				"Set VULTURE_AGENT_TOKEN to a strong shared secret, or set " +
				"VULTURE_LOCAL_MODE=true for single-host dev deployments")
	}
	return nil
}

// validateLoopbackForLocalMode returns an error if LocalMode is on AND
// the listen address would bind anything other than a loopback
// interface. The pattern is: when an operator enables LocalMode, the
// server seeds an admin user with a CSPRNG password — exposing that
// over a public interface defeats the seed gate.
func validateLoopbackForLocalMode(addr string, localMode bool) error {
	if !localMode {
		return nil
	}
	if !isLoopbackBind(addr) {
		return fmt.Errorf(
			"VULTURE_LOCAL_MODE is enabled but listen address %q is not "+
				"loopback — refuse to start. Bind to 127.0.0.1, ::1, or "+
				"localhost, or set VULTURE_LOCAL_MODE=false",
			addr,
		)
	}
	return nil
}

// isLoopbackHost reports whether `host` (the Request.Host field — may
// or may not include a :port) refers to a loopback target. Used by the
// local-session handler as defence-in-depth: an attacker who reaches
// the endpoint via a non-loopback Host (DNS rebinding, mis-routed
// reverse proxy) is rejected even if the bind-gate at H9 is bypassed.
//
// Empty host counts as loopback (test harnesses + bare HTTP/1.1 without
// a Host header default to the listening interface, which is always
// loopback when LocalMode is on).
func isLoopbackHost(host string) bool {
	if host == "" {
		return true
	}
	// Strip port if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// IPv6 bracket form when no port was present.
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// addCORSWithAllowlist replaces the previous wildcard-CORS middleware.
// Behaviour:
//   - If the request's Origin matches an entry in `allowed`, that exact
//     origin string is echoed back in Access-Control-Allow-Origin.
//   - On any other origin (or empty origin), the header is OMITTED so
//     browsers reject the cross-origin request — never `*`.
//   - Allow-Credentials: true is only set when an origin matches, so
//     the forbidden (origin=`*`, credentials=true) combination is
//     structurally impossible.
//
// Other CORS headers (Methods, Headers, Max-Age) are preserved.
// The empty allowlist is the strict-default — no cross-origin allowed.
func addCORSWithAllowlist(next http.Handler, allowed []string) *http.ServeMux {
	mux := http.NewServeMux()
	allowSet := make(map[string]struct{}, len(allowed))
	for _, o := range allowed {
		o = strings.TrimSpace(o)
		if o != "" {
			allowSet[o] = struct{}{}
		}
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Security headers retained from the previous middleware.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy",
			"camera=(), microphone=(), geolocation=()")
		// L2 audit: drop deprecated X-XSS-Protection (current browsers
		// ignore it or actively introduce side-channels).
		// L3 audit: minimal CSP — self-only by default, locks down
		// inline scripts unless the application overrides per-route.
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		// L1 audit: HSTS only on HTTPS; TLS terminator may be upstream
		// so check the X-Forwarded-Proto header in addition to r.TLS.
		if r.TLS != nil || strings.EqualFold(
			r.Header.Get("X-Forwarded-Proto"), "https") {
			w.Header().Set("Strict-Transport-Security",
				"max-age=31536000; includeSubDomains")
		}

		// CORS — allowlist-driven.
		origin := r.Header.Get("Origin")
		if origin != "" {
			if _, ok := allowSet[origin]; ok {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}
		w.Header().Set("Access-Control-Allow-Methods",
			"GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers",
			"Content-Type, Accept, Authorization")
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
