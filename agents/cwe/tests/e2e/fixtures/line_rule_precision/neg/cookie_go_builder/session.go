package session

import "net/http"

func isHTTPS(r *http.Request) bool { return r.TLS != nil }

// sessionCookie is the session cookie: HttpOnly, SameSite=Strict, and Secure
// whenever the request came over HTTPS.
func sessionCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	https := isHTTPS(r)
	return &http.Cookie{
		Name: "app_session", Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: https, SameSite: http.SameSiteStrictMode,
	}
}

func audit(name string) {}

func touch(name string) {}

// setSession issues the session cookie holding token.
func setSession(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, sessionCookie(r, token, 3600)) // EXPECT: clean
}

// clearSession deletes the session cookie.
func clearSession(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, sessionCookie(r, "", -1)) // EXPECT: clean
}
