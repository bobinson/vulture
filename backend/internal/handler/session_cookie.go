package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

// Browser sessions (0102, CWE-922). A sign-in (login, register, local
// session) that carries CSRFHeader is answered with an HttpOnly,
// SameSite=Strict session cookie instead of a body token, so no page script
// can read the JWT. A sign-in without the header (the CLI, CI clients,
// scripts) is answered exactly as before and keeps using a Bearer header.

// CSRFHeader is the header the SPA sends with every fetch. A cross-origin page
// cannot add it without a CORS preflight, and the preflight never approves
// it, so a cookie-authenticated request that carries it came from the SPA.
const CSRFHeader = "X-Vulture-CSRF"

const (
	// plainSessionCookie holds the session on plain HTTP.
	plainSessionCookie = "vulture_session"
	// hostSessionCookie holds it on HTTPS. Browsers accept a __Host- cookie
	// only when it is Secure, host-only and Path=/, so a sibling host cannot
	// plant one.
	hostSessionCookie = "__Host-vulture_session"
	// sessionMaxAge is the cookie's lifetime in seconds: the JWT's.
	sessionMaxAge = int(service.SessionTTL / time.Second)
)

// IsHTTPSRequest reports whether the client reached Vulture over HTTPS: TLS
// on this hop, or a TLS proxy's X-Forwarded-Proto (matched case-insensitively).
func IsHTTPSRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// PrincipalRateKey keys a rate limit on the request's principal, never on
// its Authorization header: "user:<id>", where an API key's principal id is
// "apikey:<id>". Without a principal it is "", and the limiter falls back to
// the client IP. Must be applied inside authMW.Require.
func PrincipalRateKey(r *http.Request) string {
	if u := getUserFromContext(r); u != nil {
		return "user:" + u.ID
	}
	return ""
}

// RequireBearerCredential refuses a request that the session cookie
// authenticated. The routes that mint or manage credentials (API keys, users)
// take a Bearer credential only, so a page cannot turn a browser session into
// a credential that outlives it. Must be applied inside authMW.Require.
func RequireBearerCredential(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if kind, _ := r.Context().Value(credKindKey).(credKind); kind == credCookie {
			writeError(w, http.StatusForbidden, "this endpoint requires a bearer credential")
			return
		}
		next(w, r)
	}
}

// hasCSRFHeader reports whether the request carries CSRFHeader.
func hasCSRFHeader(r *http.Request) bool { return r.Header.Get(CSRFHeader) != "" }

// writeCSRFRequired answers 403 to a request that needed CSRFHeader and came
// without it. A tab opened before the upgrade sends no header, hence the
// advice to reload.
func writeCSRFRequired(w http.ResponseWriter) {
	writeError(w, http.StatusForbidden, "cookie-authenticated requests must send X-Vulture-CSRF; reload the page")
}

// sessionCookieName is the name the session cookie is issued under.
func sessionCookieName(https bool) string {
	if https {
		return hostSessionCookie
	}
	return plainSessionCookie
}

// sessionCookie is the session cookie for r holding value for maxAge seconds
// (negative deletes it): HttpOnly, SameSite=Strict, host-only (no Domain),
// Path=/, and Secure under the __Host- name when r came over HTTPS.
func sessionCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	https := IsHTTPSRequest(r)
	return &http.Cookie{
		Name: sessionCookieName(https), Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: https, SameSite: http.SameSiteStrictMode,
	}
}

// setSessionCookie issues the session cookie holding token.
func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, sessionCookie(r, token, sessionMaxAge))
}

// clearSessionCookie deletes the session cookie (Max-Age=0 on the wire).
func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, sessionCookie(r, "", -1))
}

// cookieSiteAllowed reports whether a request with this Sec-Fetch-Site may
// present the session cookie: the SPA's own fetches ("same-origin"), a
// navigation the user started ("none"), or a client that sends no
// Sec-Fetch-Site at all. A same-site or cross-site request may not.
func cookieSiteAllowed(site string) bool {
	switch site {
	case "", "same-origin", "none":
		return true
	}
	return false
}

// acceptsSessionName reports whether a cookie named name holds the session:
// the __Host- name always, the plain name only on plain HTTP.
func acceptsSessionName(name string, https bool) bool {
	return name == hostSessionCookie || (name == plainSessionCookie && !https)
}

// sessionCookieToken returns the session cookie's value, or "" when the
// request presents none that counts. The Cookie header is parsed once.
func sessionCookieToken(r *http.Request) string {
	if !cookieSiteAllowed(r.Header.Get("Sec-Fetch-Site")) {
		return ""
	}
	https := IsHTTPSRequest(r)
	for _, c := range r.Cookies() {
		if acceptsSessionName(c.Name, https) {
			return c.Value
		}
	}
	return ""
}

// prepareSession turns a sign-in answer into a browser session when the
// request carries CSRFHeader: it sets the session cookie, takes the token out
// of the body and keeps the answer out of every cache. It does not write the
// body; the caller's writeJSON does. Without the header nothing changes.
func prepareSession(w http.ResponseWriter, r *http.Request, resp *model.AuthResponse) {
	if !hasCSRFHeader(r) {
		return
	}
	setSessionCookie(w, r, resp.Token)
	resp.Token = ""
	w.Header().Set("Cache-Control", "no-store")
}
