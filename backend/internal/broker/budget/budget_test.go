package budget

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newManagerUnderTest returns the Manager implementation exercised by the
// contract tests, wired to the supplied DB and shard count.
//
// RED PHASE: the real constructor does not exist yet, so this returns the
// StubManager whose every method yields ErrNotImplemented. Every contract
// test below therefore FAILS until a module agent replaces this with the
// real NewManager(db, shardCount, ...) and the tests go green. Do NOT weaken
// the assertions to match the stub — the assertions are the contract.
func newManagerUnderTest(db DB, shardCount int) Manager {
	return NewManager(db, shardCount)
}

const testTTL = 30 * time.Second

func ctx() context.Context { return context.Background() }

// --- Happy path: sharded CAS reserve-if-under-cap -------------------------

func TestReserve_UnderCap_Succeeds(t *testing.T) {
	db := newFakeDB()
	db.setCap("local", 4, 100.0) // 4 shards, $100 total
	m := newManagerUnderTest(db, 4)

	res, err := m.Reserve(ctx(), ReserveRequest{
		RunID: "run-1", RequestID: "req-1", TenantID: "local",
		EstimatedUSD: 10.0, ModelSnapshot: "gpt-4o@2025", LeaseTTL: testTTL,
	})
	if err != nil {
		t.Fatalf("Reserve under cap: unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("Reserve returned nil reservation")
	}
	if res.ReservedUSD != 10.0 {
		t.Errorf("ReservedUSD = %v, want 10.0", res.ReservedUSD)
	}
	if res.RunID != "run-1" || res.RequestID != "req-1" {
		t.Errorf("reservation identity = %q/%q, want run-1/req-1", res.RunID, res.RequestID)
	}
	if res.ModelSnapshot != "gpt-4o@2025" {
		t.Errorf("ModelSnapshot = %q, want gpt-4o@2025", res.ModelSnapshot)
	}
	if res.ExpiresAt.IsZero() {
		t.Error("reservation must carry a non-zero lease ExpiresAt (TTL)")
	}
	if got := db.leaseCount(); got != 1 {
		t.Errorf("expected exactly 1 lease persisted, got %d", got)
	}
}

// A single reservation cannot exceed the per-shard cap. With a total of $100
// over 4 shards, each shard caps at $25, so a single $40 request must be
// rejected even though the tenant total is $100.
func TestReserve_ExceedsShardCap_Rejected(t *testing.T) {
	db := newFakeDB()
	db.setCap("local", 4, 100.0) // per-shard cap = $25
	m := newManagerUnderTest(db, 4)

	_, err := m.Reserve(ctx(), ReserveRequest{
		RunID: "run-1", RequestID: "req-1", TenantID: "local",
		EstimatedUSD: 40.0, ModelSnapshot: "gpt-4o@2025", LeaseTTL: testTTL,
	})
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("Reserve over shard cap: err = %v, want ErrBudgetExceeded", err)
	}
	if got := db.leaseCount(); got != 0 {
		t.Errorf("rejected reserve must persist no lease, got %d", got)
	}
}

// Reserving up to the cap succeeds; the next reserve that would push a shard
// past its cap is rejected. Single-shard tenant makes the arithmetic exact.
func TestReserve_AtCapBoundary(t *testing.T) {
	db := newFakeDB()
	db.setCap("local", 1, 50.0) // one shard, $50
	m := newManagerUnderTest(db, 1)

	if _, err := m.Reserve(ctx(), ReserveRequest{
		RunID: "r", RequestID: "a", TenantID: "local",
		EstimatedUSD: 50.0, ModelSnapshot: "m", LeaseTTL: testTTL,
	}); err != nil {
		t.Fatalf("reserve exactly at cap should succeed: %v", err)
	}
	// Now the shard is full; even $0.01 more must be rejected.
	if _, err := m.Reserve(ctx(), ReserveRequest{
		RunID: "r", RequestID: "b", TenantID: "local",
		EstimatedUSD: 0.01, ModelSnapshot: "m", LeaseTTL: testTTL,
	}); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("reserve past full cap: err = %v, want ErrBudgetExceeded", err)
	}
}

// --- Remaining = Σ shards + ledger ----------------------------------------

func TestRemaining_ReflectsReservationsAndLedger(t *testing.T) {
	db := newFakeDB()
	db.setCap("local", 2, 100.0) // $100 total
	m := newManagerUnderTest(db, 2)

	if got, _ := m.Remaining(ctx(), "local"); got != 100.0 {
		t.Fatalf("initial Remaining = %v, want 100.0", got)
	}

	res, err := m.Reserve(ctx(), ReserveRequest{
		RunID: "run-1", RequestID: "req-1", TenantID: "local",
		EstimatedUSD: 30.0, ModelSnapshot: "m", LeaseTTL: testTTL,
	})
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// An outstanding reservation reduces remaining even before reconcile.
	if got, _ := m.Remaining(ctx(), "local"); got != 70.0 {
		t.Errorf("Remaining after reserve = %v, want 70.0", got)
	}

	// Reconcile at a LOWER actual cost ($20 vs $30 reserved): remaining must
	// reflect actual spend, not the reservation.
	_ = res
	if err := m.Reconcile(ctx(), LedgerEntry{
		RunID: "run-1", RequestID: "req-1", TenantID: "local",
		Model: "m", Provider: "openai", InputTokens: 100, OutputTokens: 50,
		CostUSD: 20.0, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got, _ := m.Remaining(ctx(), "local"); got != 80.0 {
		t.Errorf("Remaining after reconcile ($20 actual) = %v, want 80.0", got)
	}
}

// --- Reconcile: atomic INSERT ledger + DELETE lease (M1) ------------------

func TestReconcile_InsertsLedgerAndDeletesLease(t *testing.T) {
	db := newFakeDB()
	db.setCap("local", 1, 100.0)
	m := newManagerUnderTest(db, 1)

	if _, err := m.Reserve(ctx(), ReserveRequest{
		RunID: "run-1", RequestID: "req-1", TenantID: "local",
		EstimatedUSD: 10.0, ModelSnapshot: "m", LeaseTTL: testTTL,
	}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if db.leaseCount() != 1 {
		t.Fatalf("expected 1 lease pre-reconcile, got %d", db.leaseCount())
	}

	if err := m.Reconcile(ctx(), LedgerEntry{
		RunID: "run-1", RequestID: "req-1", TenantID: "local",
		Model: "m", Provider: "openai", CostUSD: 9.0, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if db.ledgerCount() != 1 {
		t.Errorf("reconcile must INSERT exactly 1 ledger row, got %d", db.ledgerCount())
	}
	if db.leaseCount() != 0 {
		t.Errorf("reconcile must DELETE the lease, %d remain", db.leaseCount())
	}
}

// Append-only, idempotent ledger: replaying the same (run_id,request_id)
// reconcile is a no-op (ON CONFLICT DO NOTHING) — never double-charges.
func TestReconcile_Idempotent_OnConflictDoNothing(t *testing.T) {
	db := newFakeDB()
	db.setCap("local", 1, 100.0)
	m := newManagerUnderTest(db, 1)

	if _, err := m.Reserve(ctx(), ReserveRequest{
		RunID: "run-1", RequestID: "req-1", TenantID: "local",
		EstimatedUSD: 10.0, ModelSnapshot: "m", LeaseTTL: testTTL,
	}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	entry := LedgerEntry{
		RunID: "run-1", RequestID: "req-1", TenantID: "local",
		Model: "m", Provider: "openai", CostUSD: 9.0, CreatedAt: time.Now(),
	}
	if err := m.Reconcile(ctx(), entry); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	// Replay: must not error and must not add a second ledger row.
	if err := m.Reconcile(ctx(), entry); err != nil {
		t.Fatalf("replayed reconcile must be a no-op, got err: %v", err)
	}
	if db.ledgerCount() != 1 {
		t.Errorf("idempotent reconcile: ledger rows = %d, want 1 (no double-charge)", db.ledgerCount())
	}
	// Remaining must reflect a single $9 charge on a $100 cap.
	if got, _ := m.Remaining(ctx(), "local"); got != 91.0 {
		t.Errorf("Remaining after idempotent replay = %v, want 91.0", got)
	}
}

// --- Sweeper: reclaims ONLY expired leases without a ledger row (M1) ------

func TestSweep_ReclaimsExpiredLeaseWithoutLedger(t *testing.T) {
	db := newFakeDB()
	db.setCap("local", 1, 100.0)
	m := newManagerUnderTest(db, 1)

	// Reserve with an already-expired TTL (negative), then never reconcile.
	if _, err := m.Reserve(ctx(), ReserveRequest{
		RunID: "run-1", RequestID: "req-1", TenantID: "local",
		EstimatedUSD: 40.0, ModelSnapshot: "m", LeaseTTL: -time.Second,
	}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// Before sweep, the reservation ties up budget.
	if got, _ := m.Remaining(ctx(), "local"); got != 60.0 {
		t.Fatalf("pre-sweep Remaining = %v, want 60.0", got)
	}

	n, err := db.SweepExpiredLeases(ctx(), time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Errorf("sweep reclaimed %d leases, want 1", n)
	}
	// Budget is freed back to full.
	if got, _ := m.Remaining(ctx(), "local"); got != 100.0 {
		t.Errorf("post-sweep Remaining = %v, want 100.0 (reservation reclaimed)", got)
	}
}

// A lease that HAS a matching ledger row (already reconciled, or a
// replica-death race where reconcile landed) must NOT be swept — that is the
// M1 double-count bug the contract forbids.
func TestSweep_SkipsLeaseWithLedgerRow(t *testing.T) {
	db := newFakeDB()
	db.setCap("local", 1, 100.0)
	m := newManagerUnderTest(db, 1)

	if _, err := m.Reserve(ctx(), ReserveRequest{
		RunID: "run-1", RequestID: "req-1", TenantID: "local",
		EstimatedUSD: 40.0, ModelSnapshot: "m", LeaseTTL: -time.Second, // expired
	}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// Reconcile removes the lease AND writes the ledger row.
	if err := m.Reconcile(ctx(), LedgerEntry{
		RunID: "run-1", RequestID: "req-1", TenantID: "local",
		Model: "m", Provider: "openai", CostUSD: 35.0, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// Sweeper must find nothing to reclaim (lease already gone + has ledger).
	n, err := db.SweepExpiredLeases(ctx(), time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 0 {
		t.Errorf("sweep reclaimed %d, want 0 (must not touch reconciled leases)", n)
	}
	if got, _ := m.Remaining(ctx(), "local"); got != 65.0 {
		t.Errorf("Remaining = %v, want 65.0 ($35 actual spend, no double free)", got)
	}
}

// A not-yet-expired lease must survive a sweep.
func TestSweep_SkipsUnexpiredLease(t *testing.T) {
	db := newFakeDB()
	db.setCap("local", 1, 100.0)
	m := newManagerUnderTest(db, 1)

	if _, err := m.Reserve(ctx(), ReserveRequest{
		RunID: "run-1", RequestID: "req-1", TenantID: "local",
		EstimatedUSD: 10.0, ModelSnapshot: "m", LeaseTTL: time.Hour, // fresh
	}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	n, err := db.SweepExpiredLeases(ctx(), time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 0 {
		t.Errorf("sweep reclaimed %d, want 0 (lease not expired)", n)
	}
	if db.leaseCount() != 1 {
		t.Errorf("unexpired lease must survive sweep, leaseCount=%d", db.leaseCount())
	}
}

// --- Concurrency: two concurrent reserves cannot exceed cap ---------------

// With a single shard capped at exactly one reservation's worth, launching
// many concurrent reserves must grant at most the cap and reject the rest —
// never overshoot. The fakeDB mutex models Postgres row-lock/CAS atomicity.
func TestReserve_Concurrent_NeverExceedsCap(t *testing.T) {
	const shardCount = 1
	const perReserve = 10.0
	const cap = 50.0 // exactly 5 reservations fit
	const goroutines = 50

	db := newFakeDB()
	db.setCap("local", shardCount, cap)
	m := newManagerUnderTest(db, shardCount)

	var granted int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := m.Reserve(ctx(), ReserveRequest{
				RunID:     "run",
				RequestID: reqID(i),
				TenantID:  "local", EstimatedUSD: perReserve,
				ModelSnapshot: "m", LeaseTTL: testTTL,
			})
			if err == nil {
				atomic.AddInt64(&granted, 1)
			} else if !errors.Is(err, ErrBudgetExceeded) {
				t.Errorf("unexpected reserve error: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	wantGranted := int64(cap / perReserve) // 5
	if granted != wantGranted {
		t.Errorf("granted %d reservations, want exactly %d (cap must not be exceeded)", granted, wantGranted)
	}
	// The total reserved across all shards must never exceed the cap.
	if got, _ := m.Remaining(ctx(), "local"); got < 0 {
		t.Errorf("Remaining went negative (%v): cap was exceeded", got)
	}
	if db.leaseCount() != int(wantGranted) {
		t.Errorf("persisted %d leases, want %d", db.leaseCount(), wantGranted)
	}
}

func reqID(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "req-0"
	}
	b := []byte{}
	for i > 0 {
		b = append([]byte{digits[i%10]}, b...)
		i /= 10
	}
	return "req-" + string(b)
}

// --- Degraded / DB error propagation --------------------------------------

// When the underlying DB reserve fails with a non-budget error (e.g. a
// transient context cancellation), Reserve must surface it rather than
// silently granting free budget.
func TestReserve_ContextCanceled_Propagates(t *testing.T) {
	db := newFakeDB()
	db.setCap("local", 1, 100.0)
	m := newManagerUnderTest(db, 1)

	c, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := m.Reserve(c, ReserveRequest{
		RunID: "run-1", RequestID: "req-1", TenantID: "local",
		EstimatedUSD: 10.0, ModelSnapshot: "m", LeaseTTL: testTTL,
	})
	if err == nil {
		t.Fatal("Reserve with canceled context must not succeed")
	}
	if db.leaseCount() != 0 {
		t.Errorf("canceled reserve must persist no lease, got %d", db.leaseCount())
	}
}
