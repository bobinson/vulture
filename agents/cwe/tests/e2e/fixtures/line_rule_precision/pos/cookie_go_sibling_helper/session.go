package session

import "net/http"

func logAccess(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name: "seen", Value: "1",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	}
}

func audit(name string) {}

func touch(name string) {}

func issue(w http.ResponseWriter, r *http.Request, tok string) {
	logAccess(r)
	http.SetCookie(w, &http.Cookie{Name: "session", Value: tok}) // EXPECT: finding
}
