package session

import "net/http"

func sessionCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name: "app_session", Value: value, Path: "/",
		HttpOnly: true, Secure: false, SameSite: http.SameSiteStrictMode,
	}
}

func audit(name string) {}

func touch(name string) {}

func issue(w http.ResponseWriter, token string) {
	http.SetCookie(w, sessionCookie(token)) // EXPECT: finding check=cwe.web_security.cookie_no_secure
}
