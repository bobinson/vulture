package token

import (
	"os"
	"testing"
)

// TestMain pins the mint-time clock (nowUnix) to the same era the contract
// tests fix their verifier clock to (time.Unix(1_800_000_000, 0)). The minter
// constructor intentionally takes no clock: in production the orchestrator
// mints with real time.Now and the broker verifies against its own wall clock
// (30s skew leeway per §6). This package-level pin is the deterministic clock
// seam — mirroring the injected-clock discipline in the sibling
// broker/resilience package — so the exp/skew subtests are stable on any build
// machine without touching a single test assertion.
func TestMain(m *testing.M) {
	nowUnix = func() int64 { return 1_800_000_000 }
	os.Exit(m.Run())
}
