package server

import (
	"net/http"

	"github.com/vulture/backend/internal/requestid"
)

// addRequestID gives every response an X-Request-ID. A client's id is adopted
// only when requestid.Valid accepts it; any other value is replaced by a
// fresh id (the request is never refused for it), so a hostile id never
// reaches a log line or a response body.
func addRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestid.Header)
		if !requestid.Valid(id) {
			id = requestid.New()
		}
		w.Header().Set(requestid.Header, id)
		next.ServeHTTP(w, r)
	})
}

// generateRequestID returns a fresh request id (requestid.New).
func generateRequestID() string { return requestid.New() }
