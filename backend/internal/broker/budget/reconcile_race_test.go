package budget

import (
	"context"
	"testing"
	"time"
)

// H3 (§26): when the sweeper reclaims an in-flight lease's reservation before
// reconcile arrives, reconcile must STILL charge actual spend — otherwise real
// provider cost lands in the ledger but never counts against the cap (silent
// under-count). Uses the fake, which models the Postgres contract.
func TestReconcile_AfterSweep_StillChargesSpent(t *testing.T) {
	db := newFakeDB()
	db.setCap("t1", 1, 100.0)
	ctx := context.Background()

	_, err := db.ReserveCAS(ctx, ReserveRequest{
		RunID: "r1", RequestID: "q1", TenantID: "t1",
		EstimatedUSD: 5.0, ModelSnapshot: "gpt-4o", LeaseTTL: -time.Second, // already expired
	}, 1)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// Sweep reclaims the expired, un-reconciled lease.
	n, err := db.SweepExpiredLeases(ctx, time.Now())
	if err != nil || n != 1 {
		t.Fatalf("sweep: n=%d err=%v, want 1,nil", n, err)
	}
	// Late reconcile of the actual $3 cost.
	if err := db.Reconcile(ctx, LedgerEntry{
		RunID: "r1", RequestID: "q1", TenantID: "t1", Model: "gpt-4o", CostUSD: 3.0,
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	rem, _ := db.Remaining(ctx, "t1")
	if want := 97.0; rem != want {
		t.Fatalf("remaining = %v, want %v (spent must reflect the $3 actual cost after sweep)", rem, want)
	}
}

// Reconcile must remain idempotent: a retried reconcile of the same
// (run_id,request_id) charges spent exactly once — the H3 fallback path must
// not double-charge on replay.
func TestReconcile_Idempotent_NoDoubleCharge(t *testing.T) {
	db := newFakeDB()
	db.setCap("t1", 1, 100.0)
	ctx := context.Background()

	_, _ = db.ReserveCAS(ctx, ReserveRequest{
		RunID: "r1", RequestID: "q1", TenantID: "t1",
		EstimatedUSD: 5.0, ModelSnapshot: "gpt-4o", LeaseTTL: time.Minute,
	}, 1)
	entry := LedgerEntry{RunID: "r1", RequestID: "q1", TenantID: "t1", Model: "gpt-4o", CostUSD: 3.0}
	for i := 0; i < 3; i++ {
		if err := db.Reconcile(ctx, entry); err != nil {
			t.Fatalf("reconcile %d: %v", i, err)
		}
	}
	rem, _ := db.Remaining(ctx, "t1")
	if want := 97.0; rem != want {
		t.Fatalf("remaining = %v, want %v (3x reconcile must charge $3 once, not $9)", rem, want)
	}
}
