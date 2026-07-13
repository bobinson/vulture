//go:build integration

// Postgres integration tests for the LLM-broker budget DB (feature 0064,
// §8). Gated by the `integration` build tag because they require a running
// Postgres addressable via POSTGRES_TEST_DSN. Normal `go test` runs skip
// these — the default suite uses the in-memory fakeDB instead.
//
// RED PHASE: NewPostgresDB does not exist yet; this file only compiles under
// `-tags=integration`, so it does not affect the default red run. It pins
// the same reserve/reconcile/sweep/idempotency contract against real SQL
// (sharded CAS row-lock, ON CONFLICT DO NOTHING, atomic reconcile txn).
//
//	Run: POSTGRES_TEST_DSN=postgres://test:test@localhost:25439/test?sslmode=disable \
//	       go test -tags=integration ./internal/broker/budget/
package budget

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func openPGForTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set; skipping integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("postgres not reachable (%v); skipping", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedShards creates a tenant with shardCount shards, each capped at
// totalCap/shardCount, using a fresh unique tenant id per test.
func seedShards(t *testing.T, sqlDB *sql.DB, tenant string, shardCount int, totalCap float64) {
	t.Helper()
	per := totalCap / float64(shardCount)
	for s := 0; s < shardCount; s++ {
		_, err := sqlDB.Exec(
			`INSERT INTO llm_budget_shard (tenant_id, shard, reserved, spent, cap)
			 VALUES ($1, $2, 0, 0, $3)
			 ON CONFLICT (tenant_id, shard) DO UPDATE SET cap = EXCLUDED.cap, reserved = 0, spent = 0`,
			tenant, s, per,
		)
		if err != nil {
			t.Fatalf("seed shard %d: %v", s, err)
		}
	}
	t.Cleanup(func() {
		_, _ = sqlDB.Exec(`DELETE FROM llm_budget_shard WHERE tenant_id=$1`, tenant)
		_, _ = sqlDB.Exec(`DELETE FROM llm_lease WHERE tenant_id=$1`, tenant)
		_, _ = sqlDB.Exec(`DELETE FROM llm_ledger WHERE tenant_id=$1`, tenant)
	})
}

func uniqueTenant(t *testing.T) string {
	return fmt.Sprintf("it-%s-%d", t.Name(), time.Now().UnixNano())
}

func TestPG_ReserveReconcileRemaining(t *testing.T) {
	sqlDB := openPGForTest(t)
	tenant := uniqueTenant(t)
	seedShards(t, sqlDB, tenant, 1, 100.0)

	db := NewPostgresDB(sqlDB) // RED: constructor not implemented yet
	ctx := context.Background()

	res, err := db.ReserveCAS(ctx, ReserveRequest{
		RunID: "run-1", RequestID: "req-1", TenantID: tenant,
		EstimatedUSD: 30.0, ModelSnapshot: "gpt-4o@2025", LeaseTTL: testTTL,
	}, 1)
	if err != nil {
		t.Fatalf("ReserveCAS: %v", err)
	}
	if res.ReservedUSD != 30.0 {
		t.Errorf("ReservedUSD = %v, want 30.0", res.ReservedUSD)
	}
	if got, _ := db.Remaining(ctx, tenant); got != 70.0 {
		t.Errorf("Remaining after reserve = %v, want 70.0", got)
	}
	if err := db.Reconcile(ctx, LedgerEntry{
		RunID: "run-1", RequestID: "req-1", TenantID: tenant,
		Model: "gpt-4o", Provider: "openai", CostUSD: 25.0, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got, _ := db.Remaining(ctx, tenant); got != 75.0 {
		t.Errorf("Remaining after reconcile = %v, want 75.0", got)
	}
}

func TestPG_Reconcile_Idempotent(t *testing.T) {
	sqlDB := openPGForTest(t)
	tenant := uniqueTenant(t)
	seedShards(t, sqlDB, tenant, 1, 100.0)

	db := NewPostgresDB(sqlDB)
	ctx := context.Background()

	if _, err := db.ReserveCAS(ctx, ReserveRequest{
		RunID: "run-1", RequestID: "req-1", TenantID: tenant,
		EstimatedUSD: 10.0, ModelSnapshot: "m", LeaseTTL: testTTL,
	}, 1); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	entry := LedgerEntry{
		RunID: "run-1", RequestID: "req-1", TenantID: tenant,
		Model: "m", Provider: "openai", CostUSD: 9.0, CreatedAt: time.Now(),
	}
	if err := db.Reconcile(ctx, entry); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if err := db.Reconcile(ctx, entry); err != nil {
		t.Fatalf("replay reconcile must be a no-op: %v", err)
	}
	var n int
	if err := sqlDB.QueryRow(
		`SELECT count(*) FROM llm_ledger WHERE run_id='run-1' AND request_id='req-1'`,
	).Scan(&n); err != nil {
		t.Fatalf("count ledger: %v", err)
	}
	if n != 1 {
		t.Errorf("ledger rows = %d, want 1 (ON CONFLICT DO NOTHING)", n)
	}
}

func TestPG_Sweep_OnlyLeasesWithoutLedger(t *testing.T) {
	sqlDB := openPGForTest(t)
	tenant := uniqueTenant(t)
	seedShards(t, sqlDB, tenant, 1, 100.0)

	db := NewPostgresDB(sqlDB)
	ctx := context.Background()

	// Expired lease, never reconciled → must be reclaimed.
	if _, err := db.ReserveCAS(ctx, ReserveRequest{
		RunID: "run-A", RequestID: "req-A", TenantID: tenant,
		EstimatedUSD: 10.0, ModelSnapshot: "m", LeaseTTL: -time.Second,
	}, 1); err != nil {
		t.Fatalf("reserve A: %v", err)
	}
	// Expired lease that HAS a ledger row → must NOT be double-reclaimed.
	if _, err := db.ReserveCAS(ctx, ReserveRequest{
		RunID: "run-B", RequestID: "req-B", TenantID: tenant,
		EstimatedUSD: 10.0, ModelSnapshot: "m", LeaseTTL: -time.Second,
	}, 1); err != nil {
		t.Fatalf("reserve B: %v", err)
	}
	if err := db.Reconcile(ctx, LedgerEntry{
		RunID: "run-B", RequestID: "req-B", TenantID: tenant,
		Model: "m", Provider: "openai", CostUSD: 8.0, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("reconcile B: %v", err)
	}
	n, err := db.SweepExpiredLeases(ctx, time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Errorf("sweep reclaimed %d, want 1 (only the no-ledger lease)", n)
	}
}

func TestPG_ConcurrentReserve_NeverExceedsCap(t *testing.T) {
	sqlDB := openPGForTest(t)
	tenant := uniqueTenant(t)
	seedShards(t, sqlDB, tenant, 1, 50.0) // single shard, exactly 5 x $10 fit

	db := NewPostgresDB(sqlDB)
	var granted int64
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := db.ReserveCAS(context.Background(), ReserveRequest{
				RunID: "run", RequestID: fmt.Sprintf("req-%d", i), TenantID: tenant,
				EstimatedUSD: 10.0, ModelSnapshot: "m", LeaseTTL: testTTL,
			}, 1)
			if err == nil {
				atomic.AddInt64(&granted, 1)
			} else if !errors.Is(err, ErrBudgetExceeded) {
				t.Errorf("unexpected err: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if granted != 5 {
		t.Errorf("granted %d, want exactly 5 (row-lock CAS must not overshoot cap)", granted)
	}
}
