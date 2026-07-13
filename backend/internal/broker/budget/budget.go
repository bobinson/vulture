// Package budget defines the LLM-broker budget/quota seam (feature 0064,
// §8): sharded per-tenant CAS reservation, leased reservations with a
// sweeper, an append-only ledger, and atomic reconcile (INSERT ledger +
// DELETE lease). It defines a DB interface the Postgres implementation
// satisfies, plus a Manager that module agents implement on top of it.

package budget

import (
	"context"
	"errors"
	"time"
)

// Sentinel budget errors (map onto §5 API error codes).
var (
	// ErrBudgetExceeded indicates the reservation would exceed the
	// tenant cap (§8) → budget_exceeded + partial-results notice.
	ErrBudgetExceeded = errors.New("broker/budget: budget exceeded")
)

// Reservation is a granted budget lease over {primary ∪ fallback} at the
// resolved model snapshot (§8). It must be reconciled (charged) or expire
// and be swept.
type Reservation struct {
	RunID         string
	RequestID     string
	TenantID      string
	Shard         int
	ReservedUSD   float64
	ModelSnapshot string
	ExpiresAt     time.Time
}

// LedgerEntry is an append-only actual-cost record, PK (run_id,request_id)
// (§8/§15).
type LedgerEntry struct {
	RunID        string
	RequestID    string
	TenantID     string
	Model        string
	Provider     string
	InputTokens  int
	OutputTokens int
	CostUSD      float64
	Estimated    bool
	CreatedAt    time.Time
}

// ReserveRequest is the input to reserve budget for one call (§8).
type ReserveRequest struct {
	RunID         string
	RequestID     string
	TenantID      string
	BudgetRef     string
	EstimatedUSD  float64
	ModelSnapshot string
	// LeaseTTL must be >= the call timeout (§8).
	LeaseTTL time.Duration
}

// DB is the storage seam the Postgres implementation satisfies (§8/§15).
// It is deliberately narrow so module agents can mock it. All operations
// are per-tenant and shard-aware.
type DB interface {
	// ReserveCAS attempts a compare-and-set reservation against a
	// (tenant,shard) row: succeeds only if reserved+spent+est <=
	// shard_cap. Returns ErrBudgetExceeded when the cap would be
	// exceeded. shardCount is the tenant's configured shard count.
	ReserveCAS(ctx context.Context, req ReserveRequest, shardCount int) (*Reservation, error)
	// Reconcile atomically INSERTs the ledger entry (ON CONFLICT DO
	// NOTHING) and DELETEs the matching lease, in one transaction (M1).
	Reconcile(ctx context.Context, entry LedgerEntry) error
	// Remaining returns Σ shards + ledger for a tenant, excluding any
	// lease that already has a ledger row (§8).
	Remaining(ctx context.Context, tenantID string) (float64, error)
	// SweepExpiredLeases reclaims only leases with NO matching ledger
	// row (fixes M1 double-count); returns the count reclaimed.
	SweepExpiredLeases(ctx context.Context, now time.Time) (int, error)
	// Ping reports DB health for the readiness ladder (§12).
	Ping(ctx context.Context) error
}

// Manager is the high-level budget seam used by the request path (§8). The
// §12 degraded-reserve local slice is descoped for P0 (§25.3): PG down ⇒ the
// replica reports not-ready and drains to skills-only.
type Manager interface {
	// Reserve grants a lease for one call via the sharded CAS.
	Reserve(ctx context.Context, req ReserveRequest) (*Reservation, error)
	// Reconcile charges actual cost and releases the lease atomically.
	Reconcile(ctx context.Context, entry LedgerEntry) error
	// Remaining reports remaining budget for a tenant.
	Remaining(ctx context.Context, tenantID string) (float64, error)
}
