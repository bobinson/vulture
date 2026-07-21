// Package conformance runs the broker store CONTRACT against every supported
// backend (feature 0064 §29). The same assertions run on SQLite (hermetic,
// always) and Postgres (when POSTGRES_TEST_DSN is set). This is the anti-drift
// guarantee for the single dialect-parameterized store impl: if SQLite and
// Postgres ever diverge on the contract, a case here fails.
package conformance

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/vulture/backend/internal/broker/budget"
	"github.com/vulture/backend/internal/broker/dialect"
	"github.com/vulture/backend/internal/broker/sqlstore"
	"github.com/vulture/backend/internal/repository"
)

// backend is one store under test: a live *sql.DB with its dialect.
type backend struct {
	name string
	dia  dialect.Kind
	db   *sql.DB
}

// backends returns the stores to exercise. SQLite is always present (hermetic
// temp file). Postgres joins when POSTGRES_TEST_DSN is set.
func backends(t *testing.T) []backend {
	t.Helper()
	out := []backend{{"sqlite", dialect.SQLite, openSQLite(t)}}
	if db := openPostgres(t); db != nil {
		out = append(out, backend{"postgres", dialect.Postgres, db})
	}
	return out
}

func openSQLite(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "broker.db")
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(30000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = db.Close() })
	if err := repository.MigrateBrokerTables(db); err != nil {
		t.Fatalf("migrate broker tables (sqlite): %v", err)
	}
	return db
}

// --- helpers -------------------------------------------------------------

// seedShard inserts one budget shard row with the given cap (idempotent).
func seedShard(t *testing.T, b backend, tenant string, shard int, cap float64) {
	t.Helper()
	q := b.dia.Rebind(`INSERT INTO llm_budget_shard (tenant_id, shard, reserved, spent, cap)
		VALUES (?, ?, 0, 0, ?) ON CONFLICT (tenant_id, shard) DO NOTHING`)
	if _, err := b.db.ExecContext(context.Background(), q, tenant, shard, cap); err != nil {
		t.Fatalf("[%s] seed shard: %v", b.name, err)
	}
}

func remaining(t *testing.T, b backend, tenant string) float64 {
	t.Helper()
	d := budget.NewSQLDB(b.db, b.dia)
	r, err := d.Remaining(context.Background(), tenant)
	if err != nil {
		t.Fatalf("[%s] remaining: %v", b.name, err)
	}
	return r
}

func scalarInt(t *testing.T, b backend, q string, args ...any) int {
	t.Helper()
	var n int
	if err := b.db.QueryRowContext(context.Background(), b.dia.Rebind(q), args...).Scan(&n); err != nil {
		t.Fatalf("[%s] scalar %q: %v", b.name, q, err)
	}
	return n
}

func reserveReq(tenant, run, req string, est float64, ttl time.Duration) budget.ReserveRequest {
	return budget.ReserveRequest{
		RunID: run, RequestID: req, TenantID: tenant, BudgetRef: tenant,
		EstimatedUSD: est, ModelSnapshot: "m", LeaseTTL: ttl,
	}
}

func ledger(tenant, run, req string, cost float64) budget.LedgerEntry {
	return budget.LedgerEntry{
		RunID: run, RequestID: req, TenantID: tenant, Model: "m", Provider: "p",
		InputTokens: 10, OutputTokens: 20, CostUSD: cost, Estimated: false, CreatedAt: time.Now(),
	}
}

// --- contract tests ------------------------------------------------------

func TestReserve_WithinCapThenExceeds(t *testing.T) {
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			tenant := "t-cap"
			seedShard(t, b, tenant, 0, 3.0)
			d := budget.NewSQLDB(b.db, b.dia)
			ctx := context.Background()
			for i := 0; i < 3; i++ {
				if _, err := d.ReserveCAS(ctx, reserveReq(tenant, "r", fmt.Sprintf("req-%d", i), 1.0, time.Minute), 1); err != nil {
					t.Fatalf("[%s] reserve %d within cap: %v", b.name, i, err)
				}
			}
			// 4th would push reserved to 4 > cap 3 → exceeded.
			if _, err := d.ReserveCAS(ctx, reserveReq(tenant, "r", "req-over", 1.0, time.Minute), 1); err != budget.ErrBudgetExceeded {
				t.Fatalf("[%s] over-cap reserve = %v, want ErrBudgetExceeded", b.name, err)
			}
		})
	}
}

func TestReserve_ConcurrentRacersRespectCap(t *testing.T) {
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			tenant := "t-race"
			const winners, racers = 5, 25
			seedShard(t, b, tenant, 0, float64(winners)) // each reserve = 1.0
			d := budget.NewSQLDB(b.db, b.dia)
			var ok int64
			var wg sync.WaitGroup
			for i := 0; i < racers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					_, err := d.ReserveCAS(context.Background(), reserveReq(tenant, "r", fmt.Sprintf("req-%d", i), 1.0, time.Minute), 1)
					if err == nil {
						atomic.AddInt64(&ok, 1)
					}
				}(i)
			}
			wg.Wait()
			if ok != winners {
				t.Fatalf("[%s] %d reservations won, want exactly %d (cap breached or over-rejected)", b.name, ok, winners)
			}
		})
	}
}

func TestReconcile_IdempotentAndMovesSpent(t *testing.T) {
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			tenant := "t-rec"
			seedShard(t, b, tenant, 0, 100.0)
			d := budget.NewSQLDB(b.db, b.dia)
			ctx := context.Background()
			if _, err := d.ReserveCAS(ctx, reserveReq(tenant, "run", "req", 1.0, time.Minute), 1); err != nil {
				t.Fatalf("[%s] reserve: %v", b.name, err)
			}
			if err := d.Reconcile(ctx, ledger(tenant, "run", "req", 2.0)); err != nil {
				t.Fatalf("[%s] reconcile: %v", b.name, err)
			}
			// Replay must be a no-op (idempotency gate = ledger ON CONFLICT).
			if err := d.Reconcile(ctx, ledger(tenant, "run", "req", 2.0)); err != nil {
				t.Fatalf("[%s] reconcile replay: %v", b.name, err)
			}
			if got := scalarInt(t, b, `SELECT COUNT(*) FROM llm_ledger WHERE run_id=? AND request_id=?`, "run", "req"); got != 1 {
				t.Fatalf("[%s] ledger rows = %d, want 1 (idempotent)", b.name, got)
			}
			if got := scalarInt(t, b, `SELECT COUNT(*) FROM llm_lease WHERE run_id=? AND request_id=?`, "run", "req"); got != 0 {
				t.Fatalf("[%s] lease rows = %d, want 0 (deleted on reconcile)", b.name, got)
			}
			// spent moved once → remaining = 100 - 2 - 0 = 98.
			if r := remaining(t, b, tenant); r < 97.999 || r > 98.001 {
				t.Fatalf("[%s] remaining = %v, want ~98 (spent charged once)", b.name, r)
			}
		})
	}
}

func TestSweep_ReclaimsExpiredUnledgeredLease_ThenReconcileFallback(t *testing.T) {
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			tenant := "t-sweep"
			seedShard(t, b, tenant, 0, 100.0)
			d := budget.NewSQLDB(b.db, b.dia)
			ctx := context.Background()
			if _, err := d.ReserveCAS(ctx, reserveReq(tenant, "run", "req", 1.0, time.Millisecond), 1); err != nil {
				t.Fatalf("[%s] reserve: %v", b.name, err)
			}
			time.Sleep(10 * time.Millisecond)
			n, err := d.SweepExpiredLeases(ctx, time.Now())
			if err != nil {
				t.Fatalf("[%s] sweep: %v", b.name, err)
			}
			if n != 1 {
				t.Fatalf("[%s] swept %d, want 1", b.name, n)
			}
			// reserved reclaimed → remaining back to full.
			if r := remaining(t, b, tenant); r < 99.999 {
				t.Fatalf("[%s] remaining after sweep = %v, want ~100", b.name, r)
			}
			// Reconcile after the sweep: lease gone → spent charged via fallback,
			// reserved stays 0 (never negative).
			if err := d.Reconcile(ctx, ledger(tenant, "run", "req", 2.0)); err != nil {
				t.Fatalf("[%s] reconcile after sweep: %v", b.name, err)
			}
			if r := remaining(t, b, tenant); r < 97.999 || r > 98.001 {
				t.Fatalf("[%s] remaining after fallback = %v, want ~98", b.name, r)
			}
		})
	}
}

func TestSweep_SkipsLedgeredLease(t *testing.T) {
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			tenant := "t-guard"
			seedShard(t, b, tenant, 0, 100.0)
			ctx := context.Background()
			// A lease that is expired BUT already has a ledger row must NOT be
			// reclaimed (M1 double-count guard).
			exec(t, b, `INSERT INTO llm_lease (run_id, request_id, tenant_id, shard, reserved, model_snapshot, expires_at)
				VALUES (?, ?, ?, 0, 1.0, 'm', ?)`, "run", "req", tenant, time.Now().Add(-time.Hour))
			exec(t, b, `INSERT INTO llm_ledger (run_id, request_id, tenant_id, model, provider, input_tokens, output_tokens, cost_usd, estimated, created_at)
				VALUES (?, ?, ?, 'm', 'p', 1, 1, 2.0, ?, ?)`, "run", "req", tenant, false, time.Now())
			d := budget.NewSQLDB(b.db, b.dia)
			n, err := d.SweepExpiredLeases(ctx, time.Now())
			if err != nil {
				t.Fatalf("[%s] sweep: %v", b.name, err)
			}
			if n != 0 {
				t.Fatalf("[%s] swept %d ledgered lease(s), want 0 (guard)", b.name, n)
			}
		})
	}
}

func TestDenylist_And_Revocation(t *testing.T) {
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			dl := sqlstore.NewDenylist(b.db, b.dia, sqlstore.DefaultCacheTTL)
			if err := dl.Deny("kid-bad"); err != nil {
				t.Fatalf("[%s] deny: %v", b.name, err)
			}
			if ok, err := dl.IsDenied("kid-bad"); err != nil || !ok {
				t.Fatalf("[%s] IsDenied(kid-bad) = %v,%v want true,nil", b.name, ok, err)
			}
			if ok, _ := dl.IsDenied("kid-ok"); ok {
				t.Fatalf("[%s] IsDenied(kid-ok) = true, want false", b.name)
			}

			rv := sqlstore.NewRevocation(b.db, b.dia, sqlstore.DefaultCacheTTL)
			if err := rv.Revoke("jti-1"); err != nil {
				t.Fatalf("[%s] revoke: %v", b.name, err)
			}
			if ok, err := rv.IsRevoked("jti-1"); err != nil || !ok {
				t.Fatalf("[%s] IsRevoked(jti-1) = %v,%v want true,nil", b.name, ok, err)
			}
			if ok, _ := rv.IsRevoked("jti-2"); ok {
				t.Fatalf("[%s] IsRevoked(jti-2) = true, want false", b.name)
			}
		})
	}
}

func TestAuditLog_WritesRow(t *testing.T) {
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			al := sqlstore.NewAuditLog(b.db, b.dia)
			al.Log(context.Background(), ledger("t-audit", "run", "req", 0.5), false)
			if got := scalarInt(t, b, `SELECT COUNT(*) FROM llm_audit_log WHERE run_id=? AND request_id=?`, "run", "req"); got != 1 {
				t.Fatalf("[%s] audit rows = %d, want 1", b.name, got)
			}
		})
	}
}

func exec(t *testing.T, b backend, q string, args ...any) {
	t.Helper()
	if _, err := b.db.ExecContext(context.Background(), b.dia.Rebind(q), args...); err != nil {
		t.Fatalf("[%s] exec %q: %v", b.name, q, err)
	}
}
