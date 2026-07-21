package budget

import (
	"context"
	"sync"
	"time"
)

// fakeDB is an in-memory DB that faithfully models the Postgres semantics
// the real implementation must provide (§8): sharded rows with a
// compare-and-set reserve, an append-only ledger keyed by
// (run_id,request_id), leases keyed the same way, and a sweeper that
// reclaims ONLY leases with no matching ledger row.
//
// A single mutex models the row-level lock / CAS atomicity that Postgres
// gives us per statement. It is the ONLY external boundary mocked here:
// all reserve/reconcile/remaining/sweep arithmetic is the real contract the
// Manager and Postgres DB must honor.
type fakeDB struct {
	mu sync.Mutex

	// shards[tenant][shard] -> row.
	shards map[string]map[int]*shardRow
	// leases keyed by run_id\x00request_id.
	leases map[string]LedgerEntryKeyed
	// ledger keyed by run_id\x00request_id.
	ledger map[string]LedgerEntry

	// pingErr, when non-nil, makes Ping fail (models PG unreachable).
	pingErr error
	// reserveHook, when set, runs inside the locked critical section right
	// after the CAS check succeeds but before state mutates — used by the
	// race test to force interleavings deterministically.
	reserveHook func()
}

type shardRow struct {
	reserved float64
	spent    float64
	cap      float64
}

// LedgerEntryKeyed holds the lease fields the fake needs to reconstruct a
// Reservation and to run the sweeper.
type LedgerEntryKeyed struct {
	RunID         string
	RequestID     string
	TenantID      string
	Shard         int
	ReservedUSD   float64
	ModelSnapshot string
	ExpiresAt     time.Time
}

func leaseKey(runID, requestID string) string { return runID + "\x00" + requestID }

func newFakeDB() *fakeDB {
	return &fakeDB{
		shards: map[string]map[int]*shardRow{},
		leases: map[string]LedgerEntryKeyed{},
		ledger: map[string]LedgerEntry{},
	}
}

// setCap distributes a total cap evenly across shardCount shards for tenant.
func (f *fakeDB) setCap(tenant string, shardCount int, totalCap float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.shards[tenant] == nil {
		f.shards[tenant] = map[int]*shardRow{}
	}
	per := totalCap / float64(shardCount)
	for s := 0; s < shardCount; s++ {
		f.shards[tenant][s] = &shardRow{cap: per}
	}
}

func (f *fakeDB) leaseCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.leases)
}

func (f *fakeDB) ledgerCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ledger)
}

// ReserveCAS models the sharded compare-and-set. It tries shards in a
// deterministic sweep starting at a pseudo-random offset; a real impl uses a
// random shard, but for tests we must be able to fill every shard, so we
// sweep. Succeeds only if reserved+spent+est <= cap on some shard.
func (f *fakeDB) ReserveCAS(ctx context.Context, req ReserveRequest, shardCount int) (*Reservation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	tenantShards := f.shards[req.TenantID]
	if tenantShards == nil {
		return nil, ErrBudgetExceeded
	}
	for s := 0; s < shardCount; s++ {
		row := tenantShards[s]
		if row == nil {
			continue
		}
		if row.reserved+row.spent+req.EstimatedUSD <= row.cap {
			if f.reserveHook != nil {
				f.reserveHook()
			}
			row.reserved += req.EstimatedUSD
			res := &Reservation{
				RunID:         req.RunID,
				RequestID:     req.RequestID,
				TenantID:      req.TenantID,
				Shard:         s,
				ReservedUSD:   req.EstimatedUSD,
				ModelSnapshot: req.ModelSnapshot,
				ExpiresAt:     time.Now().Add(req.LeaseTTL),
			}
			f.leases[leaseKey(req.RunID, req.RequestID)] = LedgerEntryKeyed{
				RunID: req.RunID, RequestID: req.RequestID, TenantID: req.TenantID,
				Shard: s, ReservedUSD: req.EstimatedUSD, ModelSnapshot: req.ModelSnapshot,
				ExpiresAt: res.ExpiresAt,
			}
			return res, nil
		}
	}
	return nil, ErrBudgetExceeded
}

// Reconcile atomically INSERTs the ledger row (ON CONFLICT DO NOTHING) and
// DELETEs the matching lease, moving reserved→spent on the lease's shard.
func (f *fakeDB) Reconcile(ctx context.Context, entry LedgerEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	k := leaseKey(entry.RunID, entry.RequestID)
	// Idempotent: spend is charged only on the FIRST ledger write (a retried
	// reconcile is a no-op, so the H3 fallback below never double-charges).
	if _, exists := f.ledger[k]; exists {
		return nil
	}
	f.ledger[k] = entry
	if lease, ok := f.leases[k]; ok {
		if row := f.shards[lease.TenantID][lease.Shard]; row != nil {
			row.reserved -= lease.ReservedUSD
			row.spent += entry.CostUSD
		}
		delete(f.leases, k)
		return nil
	}
	// H3 Case B: the lease was already swept (reserved returned by the sweep),
	// so charge actual spend to the tenant's lowest shard — the aggregate
	// remaining still reflects real cost even without the lease row.
	if row := f.lowestShard(entry.TenantID); row != nil {
		row.spent += entry.CostUSD
	}
	return nil
}

// lowestShard returns the tenant's lowest-numbered shard row (mirrors the
// Postgres MIN(shard) fallback), or nil if the tenant has none.
func (f *fakeDB) lowestShard(tenant string) *shardRow {
	rows := f.shards[tenant]
	if len(rows) == 0 {
		return nil
	}
	min := -1
	for s := range rows {
		if min == -1 || s < min {
			min = s
		}
	}
	return rows[min]
}

// Remaining = Σ (cap - spent) − outstanding reserved-without-ledger.
// Concretely: cap − spent − reserved for leases that have NO ledger row.
func (f *fakeDB) Remaining(ctx context.Context, tenantID string) (float64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	rows := f.shards[tenantID]
	if rows == nil {
		return 0, nil
	}
	var remaining float64
	for _, row := range rows {
		remaining += row.cap - row.spent - row.reserved
	}
	return remaining, nil
}

// SweepExpiredLeases reclaims ONLY expired leases with NO matching ledger
// row (fixes M1 double-count). Returns the count reclaimed.
func (f *fakeDB) SweepExpiredLeases(ctx context.Context, now time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	n := 0
	for k, lease := range f.leases {
		if _, hasLedger := f.ledger[k]; hasLedger {
			continue // reconcile already handled this one
		}
		if lease.ExpiresAt.After(now) {
			continue // not yet expired
		}
		if row := f.shards[lease.TenantID][lease.Shard]; row != nil {
			row.reserved -= lease.ReservedUSD
		}
		delete(f.leases, k)
		n++
	}
	return n, nil
}

func (f *fakeDB) Ping(ctx context.Context) error { return f.pingErr }

// Compile-time assertion the fake satisfies the DB seam.
var _ DB = (*fakeDB)(nil)
