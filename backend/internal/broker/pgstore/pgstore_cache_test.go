package pgstore

import (
	"errors"
	"testing"
	"time"
)

// The cache serves a fresh value without re-probing, so the per-verify hot path
// does not hit Postgres every call.
func TestFlagCache_CachesFreshValue(t *testing.T) {
	probes := 0
	now := time.Unix(0, 0)
	c := newFlagCache(2*time.Second, 100, func() time.Time { return now }, func(string) (bool, error) {
		probes++
		return true, nil
	})
	for i := 0; i < 5; i++ {
		v, err := c.get("k")
		if err != nil || !v {
			t.Fatalf("get = %v,%v want true,nil", v, err)
		}
	}
	if probes != 1 {
		t.Fatalf("probes = %d, want 1 (cached)", probes)
	}
}

// A revocation added upstream becomes visible once the TTL elapses (bounded
// propagation of an emergency kill, §6).
func TestFlagCache_ReprobesAfterTTL(t *testing.T) {
	now := time.Unix(0, 0)
	backing := false
	c := newFlagCache(2*time.Second, 100, func() time.Time { return now }, func(string) (bool, error) {
		return backing, nil
	})
	if v, _ := c.get("k"); v {
		t.Fatal("want false initially")
	}
	backing = true                 // upstream revocation
	now = now.Add(3 * time.Second) // past TTL
	if v, _ := c.get("k"); !v {
		t.Fatal("want true after TTL — stale cache did not refresh")
	}
}

// invalidate makes a just-written revocation visible immediately on this replica.
func TestFlagCache_InvalidateForcesReprobe(t *testing.T) {
	now := time.Unix(0, 0)
	backing := false
	c := newFlagCache(time.Hour, 100, func() time.Time { return now }, func(string) (bool, error) {
		return backing, nil
	})
	_, _ = c.get("k") // caches false
	backing = true
	c.invalidate("k")
	if v, _ := c.get("k"); !v {
		t.Fatal("want true after invalidate")
	}
}

// A probe (backing store) error is returned and NOT cached — the caller wraps
// it fail-closed, and the next call retries the store.
func TestFlagCache_ProbeErrorPropagatesAndIsNotCached(t *testing.T) {
	now := time.Unix(0, 0)
	fail := true
	boom := errors.New("pg down")
	calls := 0
	c := newFlagCache(time.Hour, 100, func() time.Time { return now }, func(string) (bool, error) {
		calls++
		if fail {
			return false, boom
		}
		return true, nil
	})
	if _, err := c.get("k"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	fail = false
	if v, err := c.get("k"); err != nil || !v {
		t.Fatalf("second get = %v,%v want true,nil (error was not cached)", v, err)
	}
	if calls != 2 {
		t.Fatalf("probe calls = %d, want 2", calls)
	}
}

// The cache is bounded: exceeding max clears it rather than growing unbounded.
func TestFlagCache_BoundedByMax(t *testing.T) {
	now := time.Unix(0, 0)
	c := newFlagCache(time.Hour, 3, func() time.Time { return now }, func(string) (bool, error) { return true, nil })
	for _, k := range []string{"a", "b", "c", "d"} {
		_, _ = c.get(k)
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n > 3 {
		t.Fatalf("cache size = %d, want <= 3 (bounded)", n)
	}
}
