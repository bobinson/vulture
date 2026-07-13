//go:build integration

package serve

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/vulture/backend/internal/config"
)

// Build must assemble a serving broker against a real Postgres (migration 024),
// and the assembled handler must answer the health/readiness probes — proving
// the composition (verifier + PG stores + budget + DBHealth) is wired.
func TestBuild_AssemblesServingBroker(t *testing.T) {
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("postgres unreachable: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	b, err := Build(config.BrokerConfig{
		Enabled: true, BudgetShards: 4, CallTimeoutSec: 30,
		ProviderAllowlist: []string{"openai"},
	}, "gpt-4o", db)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(b.Close)
	if !b.Enabled || b.Handler == nil {
		t.Fatal("Build returned a disabled/handler-less broker")
	}

	for _, path := range []string{"/livez", "/readyz"} {
		rr := httptest.NewRecorder()
		b.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200 (healthy DB): %s", path, rr.Code, rr.Body.String())
		}
	}

	// A minted token verifies + carries the right scope end-to-end.
	tok, err := b.MintForAgent("run-int", "scan", "gpt-4o")
	if err != nil || tok == "" {
		t.Fatalf("MintForAgent = %q,%v", tok, err)
	}
	b.RevokeRun("run-int") // must not error against the real revocation store
}
