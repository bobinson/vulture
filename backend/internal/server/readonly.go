package server

import (
	"encoding/json"
	"net/http"
)

// ReadOnlyGuard wraps a handler so that when readOnly is true, only GET,
// HEAD, and OPTIONS requests are allowed. Mutating methods return 503
// Service Unavailable with a clear error body.
//
// When readOnly is false this is a pass-through (no overhead per request
// beyond a single boolean check captured in the closure at route setup).
func ReadOnlyGuard(readOnly bool, next http.HandlerFunc) http.HandlerFunc {
	if !readOnly {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next(w, r)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "read-only mode: this Vulture instance does not accept writes",
				"hint":  "run audits on the writer backend; this instance only serves stored results",
			})
		}
	}
}
