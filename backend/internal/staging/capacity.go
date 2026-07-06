package staging

import (
	"context"
	"fmt"
	"os"
	"strconv"
)

// capacityMargin is the safety factor applied to the source tree size
// when checking free space in AuditsDir (LLD P0d disk-budget guard).
const capacityMargin = 1.2

// defaultMaxConcurrent bounds simultaneous stagings when
// VULTURE_STAGING_MAX_CONCURRENT is unset (LLD P0d concurrency cap):
// peak disk = Σ concurrent staged trees.
const defaultMaxConcurrent = 4

// HasCapacity is the pure disk-budget predicate: free >= src*margin.
func HasCapacity(srcBytes, freeBytes int64, margin float64) bool {
	return float64(freeBytes) >= float64(srcBytes)*margin
}

// ensureCapacityFor refuses to stage when the filesystem holding
// auditsDir lacks free space for a source tree of the given (already
// walk-computed) size plus margin. The size comes from Stage's single
// collectEntries walk, so the guard reflects exactly what would land on
// disk without a second stat-walk.
func ensureCapacityFor(size int64, auditsDir string) error {
	if err := os.MkdirAll(auditsDir, 0o755); err != nil {
		return err
	}
	free, err := freeBytes(auditsDir)
	if err != nil {
		return err
	}
	if !HasCapacity(size, free, capacityMargin) {
		return fmt.Errorf("insufficient disk in %s: tree needs %d bytes (×%.1f margin), only %d free",
			auditsDir, size, capacityMargin, free)
	}
	return nil
}

// stagingSem bounds concurrent stagings; buffered-chan semaphore sized
// once at init from the environment.
var stagingSem = make(chan struct{}, maxConcurrent())

func maxConcurrent() int {
	n, err := strconv.Atoi(os.Getenv("VULTURE_STAGING_MAX_CONCURRENT"))
	if err != nil || n <= 0 {
		return defaultMaxConcurrent
	}
	return n
}

func acquireSlot(ctx context.Context) error {
	select {
	case stagingSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseSlot() { <-stagingSem }
