// This file implements the real Manager over the DB seam (feature 0064, §8).
// The Manager is a thin request-path wrapper: it delegates the sharded CAS
// reserve, the atomic reconcile, and the remaining computation to the DB,
// carrying the tenant's configured shard count. Keeping the arithmetic in the
// DB layer (fakeDB for unit tests, Postgres for production) means the Manager
// stays trivial and every path is exercised against the same contract.
package budget

import (
	"context"
	"fmt"
)

// manager is the concrete Manager. It holds the DB seam plus the tenant shard
// count used by the sharded CAS reserve.
type manager struct {
	db         DB
	shardCount int
}

// NewManager wires a Manager to a DB and shard count. shardCount is clamped to
// at least 1 so a mis-configured tenant still resolves to a single shard
// rather than reserving against zero shards.
func NewManager(db DB, shardCount int) Manager {
	if shardCount < 1 {
		shardCount = 1
	}
	return &manager{db: db, shardCount: shardCount}
}

// Reserve grants a lease for one call via the sharded CAS. A budget rejection
// (ErrBudgetExceeded) is surfaced unwrapped so callers can errors.Is it; any
// other DB error is wrapped with context.
func (m *manager) Reserve(ctx context.Context, req ReserveRequest) (*Reservation, error) {
	res, err := m.db.ReserveCAS(ctx, req, m.shardCount)
	if err != nil {
		return nil, wrapReserveErr(err)
	}
	return res, nil
}

// Reconcile charges actual cost and releases the lease atomically.
func (m *manager) Reconcile(ctx context.Context, entry LedgerEntry) error {
	if err := m.db.Reconcile(ctx, entry); err != nil {
		return fmt.Errorf("reconcile: %w", err)
	}
	return nil
}

// Remaining reports remaining budget for a tenant.
func (m *manager) Remaining(ctx context.Context, tenantID string) (float64, error) {
	remaining, err := m.db.Remaining(ctx, tenantID)
	if err != nil {
		return 0, fmt.Errorf("remaining: %w", err)
	}
	return remaining, nil
}

// wrapReserveErr preserves the ErrBudgetExceeded sentinel for errors.Is while
// wrapping unexpected failures with context (no request content is logged).
func wrapReserveErr(err error) error {
	if err == ErrBudgetExceeded {
		return err
	}
	return fmt.Errorf("reserve: %w", err)
}

// Compile-time assertion the concrete manager satisfies the Manager seam.
var _ Manager = (*manager)(nil)
