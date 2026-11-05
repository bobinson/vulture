package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// AC9 / A7: the loaded-window probe is an OUTBOUND call from the broker to its
// upstream; it adds no broker route. The broker still serves exactly its four
// routes, and in particular no models listing or runtime passthrough an agent
// could use to reach the upstream. Regression pin: passes today.
func TestHandler_RegistersExactlyTheFourBrokerRoutes(t *testing.T) {
	mux, ok := New(Dependencies{}).Handler().(*http.ServeMux)
	if !ok {
		t.Fatal("Handler() is no longer a *http.ServeMux; update this pin to enumerate its routes")
	}
	for _, p := range []string{completePath, embedPath, livezPath, readyzPath} {
		assertRoute(t, mux, p, p)
	}
	for _, p := range []string{"/v1/models", "/api/v0/models", "/api/show", "/models", "/v1/context_window", "/probe"} {
		assertRoute(t, mux, p, "")
	}
}

// assertRoute fails unless path matches wantPattern ("" = no route).
func assertRoute(t *testing.T, mux *http.ServeMux, path, wantPattern string) {
	t.Helper()
	if got := routeFor(mux, path); got != wantPattern {
		t.Errorf("route %s: matched pattern %q, want %q", path, got, wantPattern)
	}
}

func routeFor(mux *http.ServeMux, path string) string {
	_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, path, nil))
	return pattern
}
