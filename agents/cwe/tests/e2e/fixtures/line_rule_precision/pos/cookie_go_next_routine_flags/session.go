package session

import "net/http"

func sessionCookie(v string) *http.Cookie { return &http.Cookie{Name: "s", Value: v} }

func audit(name string) {}

func touch(name string) {}

func setSession(w http.ResponseWriter, tok string) {
	http.SetCookie(w, sessionCookie(tok)) // EXPECT: finding
}

func prefsCookie(v string) *http.Cookie {
	return &http.Cookie{
		Name: "p", Value: v,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	}
}
