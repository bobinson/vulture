package session

import "net/http"

func audit(name string) {}

// login sets an unflagged session cookie; a flagged one follows further down.
func login(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: tok}) // EXPECT: finding
	audit("login")
	audit("again")
	audit("more")
	audit("done")
	http.SetCookie(w, &http.Cookie{
		Name: "prefs", Value: "1",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}
