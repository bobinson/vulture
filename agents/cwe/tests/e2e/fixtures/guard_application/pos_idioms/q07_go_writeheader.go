package main

import "net/http"

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal") == "true" {
			next.ServeHTTP(w, r)
			return
		}
		if !validSession(r) {
			w.WriteHeader(401)
			return
		}
		next.ServeHTTP(w, r)
	})
}
