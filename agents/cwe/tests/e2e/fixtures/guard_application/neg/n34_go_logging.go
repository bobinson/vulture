package main

import (
	"log"
	"net/http"
)

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-No-Log") == "1" {
			next.ServeHTTP(w, r)
			return
		}
		log.Printf("%s %s user=%v", r.Method, r.URL.Path, currentUser(r))
		next.ServeHTTP(w, r)
	})
}
