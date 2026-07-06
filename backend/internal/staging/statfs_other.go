//go:build !linux

package staging

import "math"

// freeBytes reports "unlimited" off linux so the best-effort disk-budget
// guard never blocks staging on platforms without Statfs_t parity.
func freeBytes(string) (int64, error) {
	return math.MaxInt64, nil
}
