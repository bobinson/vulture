var internalSecret = "dev"

func init() {
	if v := os.Getenv("INTERNAL_SECRET"); v != "" { internalSecret = v }
}

func mw(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Key") == internalSecret {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}
