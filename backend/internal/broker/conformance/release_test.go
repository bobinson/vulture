package conformance

import (
	"context"
	"testing"
	"time"

	"github.com/vulture/backend/internal/broker/budget"
)

// A request that fails hands its lease back at once instead of holding the
// reservation until the sweeper returns it, uncharged, after the lease expires:
// only a success is ever reconciled. Leases are now sized to outlive the
// admission queue as well as the call, so waiting for the sweeper would hold a
// dead reservation against a capped budget for many minutes.

func releaser(t *testing.T, b backend) budget.Releaser {
	t.Helper()
	r, ok := budget.NewSQLDB(b.db, b.dia).(budget.Releaser)
	if !ok {
		t.Fatalf("[%s] the SQL budget store must implement budget.Releaser", b.name)
	}
	return r
}

func TestRelease_ReturnsTheReservationAndDropsTheLease(t *testing.T) {
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			tenant := "t-release"
			seedShard(t, b, tenant, 0, 100.0)
			d := budget.NewSQLDB(b.db, b.dia)
			ctx := context.Background()
			if _, err := d.ReserveCAS(ctx, reserveReq(tenant, "run", "req", 10.0, time.Hour), 1); err != nil {
				t.Fatalf("[%s] reserve: %v", b.name, err)
			}
			if r := remaining(t, b, tenant); r < 89.999 || r > 90.001 {
				t.Fatalf("[%s] remaining after reserve = %v, want ~90", b.name, r)
			}

			rel := releaser(t, b)
			if err := rel.Release(ctx, "run", "req"); err != nil {
				t.Fatalf("[%s] release: %v", b.name, err)
			}
			if got := scalarInt(t, b, `SELECT COUNT(*) FROM llm_lease WHERE run_id=? AND request_id=?`, "run", "req"); got != 0 {
				t.Fatalf("[%s] lease rows after release = %d, want 0", b.name, got)
			}
			if r := remaining(t, b, tenant); r < 99.999 || r > 100.001 {
				t.Fatalf("[%s] remaining after release = %v, want ~100 (reservation returned)", b.name, r)
			}
			// Idempotent: a second release (or a later sweep) returns nothing twice.
			if err := rel.Release(ctx, "run", "req"); err != nil {
				t.Fatalf("[%s] second release: %v", b.name, err)
			}
			if r := remaining(t, b, tenant); r < 99.999 || r > 100.001 {
				t.Fatalf("[%s] remaining after a repeated release = %v, want ~100", b.name, r)
			}
			if n, err := d.SweepExpiredLeases(ctx, time.Now().Add(2*time.Hour)); err != nil || n != 0 {
				t.Fatalf("[%s] sweep after release = (%d, %v), want (0, nil)", b.name, n, err)
			}
		})
	}
}

// A lease whose call was charged is settled; a stray release must not hand its
// reservation back a second time or touch the charged spend.
func TestRelease_AfterReconcileIsANoOp(t *testing.T) {
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			tenant := "t-release-rec"
			seedShard(t, b, tenant, 0, 100.0)
			d := budget.NewSQLDB(b.db, b.dia)
			ctx := context.Background()
			if _, err := d.ReserveCAS(ctx, reserveReq(tenant, "run", "req", 10.0, time.Hour), 1); err != nil {
				t.Fatalf("[%s] reserve: %v", b.name, err)
			}
			if err := d.Reconcile(ctx, ledger(tenant, "run", "req", 3.0)); err != nil {
				t.Fatalf("[%s] reconcile: %v", b.name, err)
			}
			if err := releaser(t, b).Release(ctx, "run", "req"); err != nil {
				t.Fatalf("[%s] release after reconcile: %v", b.name, err)
			}
			if r := remaining(t, b, tenant); r < 96.999 || r > 97.001 {
				t.Fatalf("[%s] remaining = %v, want ~97 (spent charged once, nothing returned twice)", b.name, r)
			}
		})
	}
}

func TestRelease_UnknownLeaseIsANoOp(t *testing.T) {
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			tenant := "t-release-none"
			seedShard(t, b, tenant, 0, 100.0)
			if err := releaser(t, b).Release(context.Background(), "run", "never-reserved"); err != nil {
				t.Fatalf("[%s] release of an unknown lease = %v, want nil", b.name, err)
			}
			if r := remaining(t, b, tenant); r < 99.999 || r > 100.001 {
				t.Fatalf("[%s] remaining = %v, want ~100", b.name, r)
			}
		})
	}
}
