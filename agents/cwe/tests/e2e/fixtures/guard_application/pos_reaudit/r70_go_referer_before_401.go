package main

func adminGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Referer() == "https://admin.example.com/" {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := r.Cookie("session"); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
