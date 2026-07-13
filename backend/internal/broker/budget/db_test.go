package budget

import (
	"context"
	"errors"
	"testing"
	"time"
)

// These tests pin the DB-seam contract (§8) directly, independent of the
// Manager. Both the fakeDB and the real Postgres DB must pass an equivalent
// suite (the integration test reuses the same assertions against a live DB).
//
// RED PHASE: these exercise the fakeDB (a test double) which already models
// the contract, but they will still fail to build/pass as a package until
// the Manager-level tests' newManagerUnderTest is backed by a real impl,
// because `go test` compiles and runs the whole package. They document the
// invariants the Postgres implementer must honor.

func TestDB_ReserveCAS_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		shardCount int
		totalCap   float64
		est        float64
		wantErr    error
	}{
		{"under per-shard cap", 4, 100.0, 10.0, nil},
		{"exactly per-shard cap", 4, 100.0, 25.0, nil},
		{"over per-shard cap", 4, 100.0, 26.0, ErrBudgetExceeded},
		{"single shard under cap", 1, 20.0, 20.0, nil},
		{"single shard over cap", 1, 20.0, 20.01, ErrBudgetExceeded},
		{"unknown tenant has no shards", 1, 0.0, 1.0, ErrBudgetExceeded},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := newFakeDB()
			if tc.totalCap > 0 {
				db.setCap("local", tc.shardCount, tc.totalCap)
			}
			_, err := db.ReserveCAS(context.Background(), ReserveRequest{
				RunID: "r", RequestID: "q", TenantID: "local",
				EstimatedUSD: tc.est, ModelSnapshot: "m", LeaseTTL: testTTL,
			}, tc.shardCount)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDB_Reconcile_MovesReservedToSpent(t *testing.T) {
	db := newFakeDB()
	db.setCap("local", 1, 100.0)

	if _, err := db.ReserveCAS(context.Background(), ReserveRequest{
		RunID: "r", RequestID: "q", TenantID: "local",
		EstimatedUSD: 30.0, ModelSnapshot: "m", LeaseTTL: testTTL,
	}, 1); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if err := db.Reconcile(context.Background(), LedgerEntry{
		RunID: "r", RequestID: "q", TenantID: "local",
		Model: "m", Provider: "openai", CostUSD: 25.0, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got, err := db.Remaining(context.Background(), "local")
	if err != nil {
		t.Fatalf("remaining: %v", err)
	}
	if got != 75.0 {
		t.Errorf("Remaining = %v, want 75.0 (reserved released, $25 spent)", got)
	}
}

func TestDB_Ping_HealthGate(t *testing.T) {
	db := newFakeDB()
	if err := db.Ping(context.Background()); err != nil {
		t.Fatalf("healthy Ping: %v", err)
	}
	db.pingErr = errors.New("pg unreachable")
	if err := db.Ping(context.Background()); err == nil {
		t.Fatal("Ping must surface DB unreachability for the readiness ladder")
	}
}
