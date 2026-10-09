package main

import "net/http"

var trusted = map[string]bool{"10.0.0.1": true}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if trusted[r.Header.Get("X-Real-IP")] {
			next.ServeHTTP(w, r)
			return
		}
		if !validSession(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
