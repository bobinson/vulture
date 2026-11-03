package session

import "net/http"

func plainCookie(value string) *http.Cookie {
	return &http.Cookie{Name: "app_session", Value: value, Path: "/"}
}

func audit(name string) {}

func touch(name string) {}

func issue(w http.ResponseWriter, token string) {
	http.SetCookie(w, plainCookie(token)) // EXPECT: finding
}
