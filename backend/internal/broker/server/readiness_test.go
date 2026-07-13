package server_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/broker/server"
)

// doGet performs a GET against the server handler.
func doGet(t *testing.T, srv *server.Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	return rr
}

// Honest readiness (§12 must-fix): the broker cannot serve without its
// budget store — a replica whose PG is down must report NOT ready, so the
// orchestrator routes agents to their skills-only fallback instead of
// letting requests fail at reserve time.
func TestReadyz_BudgetStoreDown_NotReady(t *testing.T) {
	h := newHealthyHarness()
	deps := h.deps()
	deps.DBHealth = func(context.Context) error { return errors.New("pg down") }
	srv := server.New(deps)

	rr := doGet(t, srv, "/readyz")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz with unhealthy budget store = %d, want 503; body=%q", rr.Code, rr.Body.String())
	}
}

// A healthy budget store keeps the replica ready.
func TestReadyz_BudgetStoreHealthy_Ready(t *testing.T) {
	h := newHealthyHarness()
	deps := h.deps()
	deps.DBHealth = func(context.Context) error { return nil }
	srv := server.New(deps)

	rr := doGet(t, srv, "/readyz")
	if rr.Code != http.StatusOK {
		t.Fatalf("readyz with healthy budget store = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
}
