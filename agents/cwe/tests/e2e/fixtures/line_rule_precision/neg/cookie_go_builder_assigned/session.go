package session

import "net/http"

func strictCookie(value string) *http.Cookie {
	c := &http.Cookie{Name: "app_session", Value: value, Path: "/"}
	c.HttpOnly = true
	c.Secure = true
	c.SameSite = http.SameSiteLaxMode
	return c
}

func audit(name string) {}

func touch(name string) {}

func issue(w http.ResponseWriter, token string) {
	c := strictCookie(token)
	http.SetCookie(w, c) // EXPECT: clean
}
