//go:build integration

// Postgres implementation of the budget DB seam (feature 0064, §8). It is
// compiled only under the `integration` build tag, alongside the integration
// tests that exercise it against a live Postgres (POSTGRES_TEST_DSN). The
// default `go test` run uses the in-memory fakeDB and never links this file,
// so the package has no hard dependency on a database at unit-test time.
//
// Schema (seeded by the integration test):
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
	"fmt"
	"time"
)

// postgresDB implements DB over a *sql.DB. Atomicity for the sharded CAS and
// the reconcile txn comes from Postgres row locks / single-statement updates,
// exactly as the fakeDB's mutex models.
type postgresDB struct {
	db *sql.DB
}

// NewPostgresDB wires the Postgres budget DB.
func NewPostgresDB(db *sql.DB) DB { return &postgresDB{db: db} }

// ReserveCAS performs the sharded compare-and-set. It picks a pseudo-random
// starting shard and sweeps forward, issuing a conditional UPDATE guarded by
// reserved+spent+est <= cap; the affected-rows count is the CAS witness. On a
// win it inserts the lease and returns the Reservation. Exhausting all shards
// without a winner yields ErrBudgetExceeded.
func (p *postgresDB) ReserveCAS(ctx context.Context, req ReserveRequest, shardCount int) (*Reservation, error) {
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

// tryReserveShard runs the guarded UPDATE for one shard; ok is true iff the
// CAS won (exactly one row updated).
func (p *postgresDB) tryReserveShard(ctx context.Context, req ReserveRequest, shard int) (bool, error) {
	res, err := p.db.ExecContext(ctx,
		`UPDATE llm_budget_shard
		    SET reserved = reserved + $1
		  WHERE tenant_id = $2 AND shard = $3
		    AND reserved + spent + $1 <= cap`,
		req.EstimatedUSD, req.TenantID, shard,
	)
	if err != nil {
		return false, fmt.Errorf("reserve cas update: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("reserve cas rows: %w", err)
	}
	if n == 0 {
		return false, nil
	}
	if err := p.insertLease(ctx, req, shard); err != nil {
		return false, err
	}
	return true, nil
}

// insertLease persists the lease row for a won CAS.
func (p *postgresDB) insertLease(ctx context.Context, req ReserveRequest, shard int) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO llm_lease
		    (run_id, request_id, tenant_id, shard, reserved, model_snapshot, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		req.RunID, req.RequestID, req.TenantID, shard, req.EstimatedUSD,
		req.ModelSnapshot, time.Now().Add(req.LeaseTTL),
	)
	if err != nil {
		return fmt.Errorf("insert lease: %w", err)
	}
	return nil
}

// buildReservation materializes the Reservation returned to the caller.
func (p *postgresDB) buildReservation(req ReserveRequest, shard int) (*Reservation, error) {
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
// the lease's reserved→spent + DELETEs the lease, all in one txn (M1). Replays
// are no-ops: a missing lease (already reconciled/swept) leaves the ledger
// untouched by the conflict clause.
func (p *postgresDB) Reconcile(ctx context.Context, entry LedgerEntry) (err error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin reconcile txn: %w", err)
	}
	defer func() { err = finishTx(tx, err) }()

	if err = insertLedger(ctx, tx, entry); err != nil {
		return err
	}
	return releaseLease(ctx, tx, entry)
}

// insertLedger appends the actual-cost row, first-writer-wins.
func insertLedger(ctx context.Context, tx *sql.Tx, e LedgerEntry) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO llm_ledger
		    (run_id, request_id, tenant_id, model, provider,
		     input_tokens, output_tokens, cost_usd, estimated, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (run_id, request_id) DO NOTHING`,
		e.RunID, e.RequestID, e.TenantID, e.Model, e.Provider,
		e.InputTokens, e.OutputTokens, e.CostUSD, e.Estimated, e.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert ledger: %w", err)
	}
	return nil
}

// releaseLease moves the lease's reserved onto spent (at actual cost) on its
// shard and deletes the lease, using the lease row's own shard/reserved so the
// arithmetic is exact even when actual cost differs from the estimate.
func releaseLease(ctx context.Context, tx *sql.Tx, e LedgerEntry) error {
	_, err := tx.ExecContext(ctx,
		`WITH l AS (
		     DELETE FROM llm_lease
		      WHERE run_id = $1 AND request_id = $2
		  RETURNING tenant_id, shard, reserved)
		 UPDATE llm_budget_shard s
		    SET reserved = s.reserved - l.reserved,
		        spent    = s.spent + $3
		   FROM l
		  WHERE s.tenant_id = l.tenant_id AND s.shard = l.shard`,
		e.RunID, e.RequestID, e.CostUSD,
	)
	if err != nil {
		return fmt.Errorf("release lease: %w", err)
	}
	return nil
}

// Remaining returns Σ (cap - spent - reserved) across the tenant's shards.
// reserved reflects only outstanding (un-reconciled) leases because Reconcile
// zeroes a lease's reserved contribution as it charges spent.
func (p *postgresDB) Remaining(ctx context.Context, tenantID string) (float64, error) {
	var remaining sql.NullFloat64
	err := p.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(cap - spent - reserved), 0)
		   FROM llm_budget_shard WHERE tenant_id = $1`,
		tenantID,
	).Scan(&remaining)
	if err != nil {
		return 0, fmt.Errorf("remaining query: %w", err)
	}
	return remaining.Float64, nil
}

// SweepExpiredLeases reclaims ONLY expired leases with NO matching ledger row
// (fixes the M1 double-count). A single statement returns reserved to the
// shard and deletes the lease; the count of deleted leases is the reclaim
// count.
func (p *postgresDB) SweepExpiredLeases(ctx context.Context, now time.Time) (int, error) {
	res, err := p.db.ExecContext(ctx,
		`WITH victims AS (
		     SELECT run_id, request_id, tenant_id, shard, reserved
		       FROM llm_lease l
		      WHERE l.expires_at <= $1
		        AND NOT EXISTS (
		            SELECT 1 FROM llm_ledger g
		             WHERE g.run_id = l.run_id AND g.request_id = l.request_id)),
		 freed AS (
		     UPDATE llm_budget_shard s
		        SET reserved = s.reserved - v.reserved
		       FROM victims v
		      WHERE s.tenant_id = v.tenant_id AND s.shard = v.shard)
		 DELETE FROM llm_lease d
		  USING victims v
		  WHERE d.run_id = v.run_id AND d.request_id = v.request_id`,
		now,
	)
	if err != nil {
		return 0, fmt.Errorf("sweep leases: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sweep rows: %w", err)
	}
	return int(n), nil
}

// Ping reports DB health for the readiness ladder (§12).
func (p *postgresDB) Ping(ctx context.Context) error {
	if err := p.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	return nil
}

// finishTx commits when the body succeeded, otherwise rolls back, preserving
// the original error. Keeps the deferred cleanup single-path and low-branch.
func finishTx(tx *sql.Tx, bodyErr error) error {
	if bodyErr != nil {
		_ = tx.Rollback()
		return bodyErr
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit reconcile txn: %w", err)
	}
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Compile-time assertion the Postgres impl satisfies the DB seam.
var _ DB = (*postgresDB)(nil)
