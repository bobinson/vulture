package serve

import (
	"testing"

	"github.com/vulture/backend/internal/broker/server"
)

// The production bulkhead must queue for exactly as long as the server sizes
// its budget leases for. Derived from the one call-timeout setting in one
// place, the two cannot drift apart: a queue bound longer than the lease
// sizing would let a queued request's lease expire and be re-spent.
func TestBulkheadConfig_QueueBoundMatchesLeaseSizing(t *testing.T) {
	for _, sec := range []int{0, 1, 439, 900} {
		cfg := bulkheadConfig(sec)
		if cfg.MaxWait != server.AdmissionWait(sec) {
			t.Fatalf("callTimeoutSec=%d: MaxWait = %v, want server.AdmissionWait = %v", sec, cfg.MaxWait, server.AdmissionWait(sec))
		}
		if cfg.MaxConcurrent != providerConcurrency || providerConcurrency < 1 {
			t.Fatalf("callTimeoutSec=%d: MaxConcurrent = %d, want providerConcurrency (%d)", sec, cfg.MaxConcurrent, providerConcurrency)
		}
	}
}
