package budget

import (
	"context"
	"testing"
)

// releasingDB is a DB that can also hand back a lease, recording what it was
// asked to release.
type releasingDB struct {
	*fakeDB
	released []string
}

func (r *releasingDB) Release(_ context.Context, runID, requestID string) error {
	r.released = append(r.released, leaseKey(runID, requestID))
	return nil
}

// The Manager exposes Release whenever its store can release, so the request
// path can hand back a lease no call will reconcile.
func TestManager_ReleaseDelegatesToAReleasingStore(t *testing.T) {
	db := &releasingDB{fakeDB: newFakeDB()}
	m, ok := NewManager(db, 1).(Releaser)
	if !ok {
		t.Fatal("the Manager must implement Releaser")
	}
	if err := m.Release(context.Background(), "run", "req"); err != nil {
		t.Fatalf("Release = %v, want nil", err)
	}
	if len(db.released) != 1 || db.released[0] != leaseKey("run", "req") {
		t.Fatalf("store released %q, want exactly the (run, req) lease", db.released)
	}
}

// A store without Release leaves the lease to the sweeper: the Manager's
// Release is then a no-op, never an error on the request path.
func TestManager_ReleaseWithoutAReleasingStoreIsANoOp(t *testing.T) {
	m, ok := NewManager(newFakeDB(), 1).(Releaser)
	if !ok {
		t.Fatal("the Manager must implement Releaser")
	}
	if err := m.Release(context.Background(), "run", "req"); err != nil {
		t.Fatalf("Release on a store that cannot release = %v, want nil (the sweeper reclaims it)", err)
	}
}
