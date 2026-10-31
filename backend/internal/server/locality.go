package server

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

// Local mode serves the local user without a password: a token-less request
// gets the local identity, /api/auth/local-session mints a token, and open
// registration is on. H9 (validateLoopbackForLocalMode) keeps the listener on
// loopback, but that alone does not make every request local. A reverse proxy
// on the same host — the dev frontend's Vite proxy — connects from loopback on
// behalf of whatever client reached it, and a DNS-rebinding page in the local
// browser reaches loopback under a foreign Host. localOnly is the one gate that
// closes both for every route: in local mode a request is served only when it
// is local end to end.

// isLocalRequest reports whether r was made on this machine end to end:
//   - the direct peer is loopback;
//   - every client address a proxy recorded (X-Forwarded-For, X-Real-IP,
//     Forwarded for=) is loopback — a proxy appends the real peer, which the
//     client cannot remove, so a forged loopback prefix does not help;
//   - the Host names a loopback target (H7: DNS rebinding).
func isLocalRequest(r *http.Request) bool {
	return isLoopbackAddr(hostOnly(r.RemoteAddr)) &&
		allLoopback(forwardedClients(r.Header)) &&
		isLoopbackHost(r.Host)
}

// localOnly serves only requests isLocalRequest accepts; anything else gets a
// JSON 403 before any route, passwordless or not, sees it.
func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLocalRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "local mode serves requests from this machine only",
		})
	})
}

// forwardedClients lists every client address a proxy in front of this server
// recorded, across the three headers in use. An obfuscated or unknown entry
// ("_hidden", "unknown") is kept and fails the loopback test: an origin the
// proxy would not name is not provably local.
func forwardedClients(h http.Header) []string {
	var out []string
	for _, v := range h.Values("X-Forwarded-For") {
		out = append(out, nonEmpty(strings.Split(v, ","))...)
	}
	out = append(out, h.Values("X-Real-IP")...)
	for _, v := range h.Values("Forwarded") {
		out = append(out, forwardedFor(v)...)
	}
	return out
}

// forwardedFor extracts the for= parameter of each element of an RFC 7239
// Forwarded header, e.g. `for=192.0.2.60;proto=http, for="[2001:db8::1]:4711"`.
func forwardedFor(v string) []string {
	var out []string
	for _, elem := range strings.Split(v, ",") {
		for _, pair := range strings.Split(elem, ";") {
			k, val, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if ok && strings.EqualFold(k, "for") {
				out = append(out, strings.Trim(val, `"`))
			}
		}
	}
	return out
}

func nonEmpty(parts []string) []string {
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func allLoopback(addrs []string) bool {
	for _, a := range addrs {
		if !isLoopbackAddr(a) {
			return false
		}
	}
	return true
}

// isLoopbackAddr reports whether s — an IP, optionally bracketed and/or with a
// port — is loopback: 127.0.0.0/8, ::1, or an IPv4-mapped 127.x address (what a
// dual-stack listener reports for an IPv4 client).
func isLoopbackAddr(s string) bool {
	s = strings.TrimSpace(s)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	ip := net.ParseIP(strings.Trim(s, "[]"))
	return ip != nil && ip.IsLoopback()
}
