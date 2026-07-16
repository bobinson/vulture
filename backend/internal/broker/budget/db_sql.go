// Dialect-parameterized SQL implementation of the budget DB seam (feature 0064
// §8, §29). ONE implementation serves both Postgres (multi-replica, Mode B) and
// SQLite (single-process, Mode A / native Mode E): queries are authored with
// `?` placeholders and rebound per dialect, atomicity uses portable
// `DELETE … RETURNING` (no Postgres-only writable CTEs), and SQLite writes are
// serialized in-process (dialect.NeedsWriteLock) so read-modify-write txns are
// atomic without row locks. Correctness is identical across engines and pinned
// by internal/broker/conformance.
//
// Schema (migration 024 for Postgres; repository.MigrateBrokerTables for SQLite):
//
//	llm_budget_shard(tenant_id, shard, reserved, spent, cap, PK(tenant_id,shard))
//	llm_lease(run_id, request_id, tenant_id, shard, reserved, model_snapshot,
//	          expires_at, PK(run_id,request_id))
//	llm_ledger(run_id, request_id, tenant_id, model, provider, input_tokens,
//	           output_tokens, cost_usd, estimated, created_at, PK(run_id,request_id))
package budget

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vulture/backend/internal/broker/dialect"
)

// sqlDB implements DB over a *sql.DB for a given dialect. writeMu is non-nil
// only for stores that need in-process write serialization (SQLite); Postgres
// leaves it nil and relies on DB-level atomicity across replicas.
type sqlDB struct {
	db      *sql.DB
	dia     dialect.Kind
	writeMu *sync.Mutex
}

// NewSQLDB wires the budget DB for the given dialect.
func NewSQLDB(db *sql.DB, dia dialect.Kind) DB {
	d := &sqlDB{db: db, dia: dia}
	if dia.NeedsWriteLock() {
		d.writeMu = &sync.Mutex{}
	}
	return d
}

// NewPostgresDB wires the Postgres budget DB (back-compat shim over NewSQLDB).
func NewPostgresDB(db *sql.DB) DB { return NewSQLDB(db, dialect.Postgres) }

// lockWrites serializes a multi-statement write txn on stores that need it
// (SQLite). Returns an unlock func to defer; a no-op on Postgres.
func (p *sqlDB) lockWrites() func() {
	if p.writeMu == nil {
		return func() {}
	}
	p.writeMu.Lock()
	return p.writeMu.Unlock
}

// ReserveCAS performs the sharded compare-and-set. It picks a pseudo-random
// starting shard and sweeps forward, issuing a conditional UPDATE guarded by
// reserved+spent+est <= cap; the affected-rows count is the CAS witness. On a
// win it inserts the lease and returns the Reservation. Exhausting all shards
// without a winner yields ErrBudgetExceeded.
func (p *sqlDB) ReserveCAS(ctx context.Context, req ReserveRequest, shardCount int) (*Reservation, error) {
	start := int(time.Now().UnixNano()) % maxInt(shardCount, 1)
	for i := 0; i < shardCount; i++ {
		shard := (start + i) % shardCount
		ok, err := p.tryReserveShard(ctx, req, shard)
		if err != nil {
			return nil, err
		}
		if ok {
			return p.buildReservation(req, shard)
		}
	}
	return nil, ErrBudgetExceeded
}

// tryReserveShard runs the guarded shard UPDATE and the lease INSERT as ONE
// transaction (§26/H2): a failed lease insert must not orphan the `reserved`
// increment. ok is true iff the CAS won AND the lease was persisted.
func (p *sqlDB) tryReserveShard(ctx context.Context, req ReserveRequest, shard int) (ok bool, err error) {
	defer p.lockWrites()()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin reserve txn: %w", err)
	}
	defer func() { err = finishReserveTx(tx, ok, err) }()

	res, err := tx.ExecContext(ctx, p.dia.Rebind(
		`UPDATE llm_budget_shard
		    SET reserved = reserved + ?
		  WHERE tenant_id = ? AND shard = ?
		    AND reserved + spent + ? <= cap`),
		req.EstimatedUSD, req.TenantID, shard, req.EstimatedUSD,
	)
	if err != nil {
		return false, fmt.Errorf("reserve cas update: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("reserve cas rows: %w", err)
	}
	if n == 0 {
		return false, nil // CAS lost on this shard — rolled back, try the next
	}
	if _, err = tx.ExecContext(ctx, p.dia.Rebind(
		`INSERT INTO llm_lease
		    (run_id, request_id, tenant_id, shard, reserved, model_snapshot, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`),
		req.RunID, req.RequestID, req.TenantID, shard, req.EstimatedUSD,
		req.ModelSnapshot, time.Now().Add(req.LeaseTTL),
	); err != nil {
		return false, fmt.Errorf("insert lease: %w", err) // rolls back the reserved increment
	}
	return true, nil
}

func finishReserveTx(tx *sql.Tx, won bool, bodyErr error) error {
	if bodyErr != nil || !won {
		_ = tx.Rollback()
		return bodyErr
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit reserve txn: %w", err)
	}
	return nil
}

func (p *sqlDB) buildReservation(req ReserveRequest, shard int) (*Reservation, error) {
	return &Reservation{
		RunID:         req.RunID,
		RequestID:     req.RequestID,
		TenantID:      req.TenantID,
		Shard:         shard,
		ReservedUSD:   req.EstimatedUSD,
		ModelSnapshot: req.ModelSnapshot,
		ExpiresAt:     time.Now().Add(req.LeaseTTL),
	}, nil
}

// Reconcile atomically INSERTs the ledger (ON CONFLICT DO NOTHING) and moves
// the lease's reserved→spent + DELETEs the lease, in one txn (M1). Replays are
// no-ops: the ledger insert's ON CONFLICT gate means a retried reconcile finds
// the row present and charges nothing.
func (p *sqlDB) Reconcile(ctx context.Context, entry LedgerEntry) (err error) {
	defer p.lockWrites()()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin reconcile txn: %w", err)
	}
	defer func() { err = finishTx(tx, err) }()

	inserted, err := p.insertLedger(ctx, tx, entry)
	if err != nil || !inserted {
		return err
	}
	return p.chargeSpent(ctx, tx, entry)
}

// insertLedger appends the actual-cost row, first-writer-wins; inserted is true
// iff this call actually wrote the row (false on ON CONFLICT).
func (p *sqlDB) insertLedger(ctx context.Context, tx *sql.Tx, e LedgerEntry) (bool, error) {
	res, err := tx.ExecContext(ctx, p.dia.Rebind(
		`INSERT INTO llm_ledger
		    (run_id, request_id, tenant_id, model, provider,
		     input_tokens, output_tokens, cost_usd, estimated, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT (run_id, request_id) DO NOTHING`),
		e.RunID, e.RequestID, e.TenantID, e.Model, e.Provider,
		e.InputTokens, e.OutputTokens, e.CostUSD, e.Estimated, e.CreatedAt,
	)
	if err != nil {
		return false, fmt.Errorf("insert ledger: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("insert ledger rows: %w", err)
	}
	return n > 0, nil
}

// chargeSpent moves the lease's reserved onto spent (at actual cost) on its
// shard and deletes the lease — atomically via DELETE … RETURNING (portable to
// Postgres + SQLite). §26/H3: if the lease was already swept, the DELETE
// returns no row and a fallback charges actual spend to the tenant's lowest
// shard, so real cost is never dropped just because the call outlived its lease.
func (p *sqlDB) chargeSpent(ctx context.Context, tx *sql.Tx, e LedgerEntry) error {
	var tenant string
	var shard int
	var reserved float64
	err := tx.QueryRowContext(ctx, p.dia.Rebind(
		`DELETE FROM llm_lease
		  WHERE run_id = ? AND request_id = ?
		 RETURNING tenant_id, shard, reserved`),
		e.RunID, e.RequestID,
	).Scan(&tenant, &shard, &reserved)
	if errors.Is(err, sql.ErrNoRows) {
		return p.chargeSpentFallback(ctx, tx, e) // lease already swept
	}
	if err != nil {
		return fmt.Errorf("release lease: %w", err)
	}
	if _, err := tx.ExecContext(ctx, p.dia.Rebind(
		`UPDATE llm_budget_shard
		    SET reserved = reserved - ?, spent = spent + ?
		  WHERE tenant_id = ? AND shard = ?`),
		reserved, e.CostUSD, tenant, shard,
	); err != nil {
		return fmt.Errorf("charge spent: %w", err)
	}
	return nil
}

// chargeSpentFallback charges actual spend to the tenant's lowest shard when no
// lease row remained (swept). reserved is untouched (the sweep already returned
// it); only spent moves, so aggregate remaining reflects real cost.
func (p *sqlDB) chargeSpentFallback(ctx context.Context, tx *sql.Tx, e LedgerEntry) error {
	_, err := tx.ExecContext(ctx, p.dia.Rebind(
		`UPDATE llm_budget_shard
		    SET spent = spent + ?
		  WHERE tenant_id = ?
		    AND shard = (SELECT MIN(shard) FROM llm_budget_shard WHERE tenant_id = ?)`),
		e.CostUSD, e.TenantID, e.TenantID,
	)
	if err != nil {
		return fmt.Errorf("charge spent fallback: %w", err)
	}
	return nil
}

// Remaining returns Σ (cap - spent - reserved) across the tenant's shards.
func (p *sqlDB) Remaining(ctx context.Context, tenantID string) (float64, error) {
	var remaining sql.NullFloat64
	err := p.db.QueryRowContext(ctx, p.dia.Rebind(
		`SELECT COALESCE(SUM(cap - spent - reserved), 0)
		   FROM llm_budget_shard WHERE tenant_id = ?`),
		tenantID,
	).Scan(&remaining)
	if err != nil {
		return 0, fmt.Errorf("remaining query: %w", err)
	}
	return remaining.Float64, nil
}

// SweepExpiredLeases reclaims ONLY expired leases with NO matching ledger row
// (fixes the M1 double-count). It deletes the victims atomically via
// DELETE … RETURNING, then returns each victim's reserved to its shard, in one
// txn. Returns the reclaim count.
func (p *sqlDB) SweepExpiredLeases(ctx context.Context, now time.Time) (n int, err error) {
	defer p.lockWrites()()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin sweep txn: %w", err)
	}
	defer func() { err = finishTx(tx, err) }()

	type victim struct {
		tenant   string
		shard    int
		reserved float64
	}
	rows, err := tx.QueryContext(ctx, p.dia.Rebind(
		`DELETE FROM llm_lease
		  WHERE expires_at <= ?
		    AND NOT EXISTS (
		        SELECT 1 FROM llm_ledger g
		         WHERE g.run_id = llm_lease.run_id AND g.request_id = llm_lease.request_id)
		 RETURNING tenant_id, shard, reserved`),
		now,
	)
	if err != nil {
		return 0, fmt.Errorf("sweep delete: %w", err)
	}
	var victims []victim
	for rows.Next() {
		var v victim
		if scanErr := rows.Scan(&v.tenant, &v.shard, &v.reserved); scanErr != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("sweep scan: %w", scanErr)
		}
		victims = append(victims, v)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("sweep rows: %w", rowsErr)
	}
	_ = rows.Close() // must close before issuing further statements on the txn
	for _, v := range victims {
		if _, uErr := tx.ExecContext(ctx, p.dia.Rebind(
			`UPDATE llm_budget_shard SET reserved = reserved - ? WHERE tenant_id = ? AND shard = ?`),
			v.reserved, v.tenant, v.shard,
		); uErr != nil {
			return 0, fmt.Errorf("sweep return reserved: %w", uErr)
		}
	}
	return len(victims), nil
}

// Ping reports DB health for the readiness ladder (§12).
func (p *sqlDB) Ping(ctx context.Context) error {
	if err := p.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	return nil
}

func finishTx(tx *sql.Tx, bodyErr error) error {
	if bodyErr != nil {
		_ = tx.Rollback()
		return bodyErr
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit txn: %w", err)
	}
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Compile-time assertion the SQL impl satisfies the DB seam.
var _ DB = (*sqlDB)(nil)
