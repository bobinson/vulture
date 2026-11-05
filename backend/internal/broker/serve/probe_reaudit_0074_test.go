package serve

// Feature 0074 re-audit R3 and R5: the loaded-window probe after an overflow
// and on a target that can never be probed.
//
//   R3 a re-probe that fails after an overflow keeps min(guess, stale): a
//      measured window that had LOWERED the guess is kept (the registry guess
//      is larger, and the model just overflowed), one above the guess is
//      dropped so the guess answers.
//   R5 a permanent verdict (a target that is not local, or one the egress
//      validator refuses after resolving) stops re-probing for good; a
//      transient failure (DNS) is still retried lazily, once per cooldown.

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// R3: the stale measured window lowered the guess (8192 < 128000), so a
// failed re-probe after an overflow keeps it rather than serving the 16x
// larger guess for the model that just overflowed.
func TestProbe_FailedReprobeKeepsALoweringStaleWindow_0074(t *testing.T) {
	shortCooldown(t)
	s := newScriptedListing(t)
	s.set(listingFor(belowGuessModel, 8_192))
	b := probeBroker(t, "openai-compatible", s.srv.URL+"/v1", belowGuessModel, true)
	pollWindow(t, b, 8_192)
	s.set("")
	time.Sleep(2 * probeCooldown)
	b.probe.onOverflow()
	afterRequestsN(t, b, s, 2)
	time.Sleep(2 * probeCooldown) // let the failed re-probe record
	w, src := windowOf(t, b)
	assertWindow(t, w, src, 8_192, "probe")
}

// countingLookup resolves every host to ip (or fails when ip is nil) and
// counts the calls: each probe attempt resolves exactly once.
func countingLookup(ip net.IP, calls *atomic.Int32) func(context.Context, string) ([]net.IP, error) {
	return func(context.Context, string) ([]net.IP, error) {
		calls.Add(1)
		if ip == nil {
			return nil, errors.New("dns down")
		}
		return []net.IP{ip}, nil
	}
}

// attemptsAfterReads starts a probe for target, reads its window for ten
// cooldowns, and returns how many attempts resolved the host.
func attemptsAfterReads(t *testing.T, target probeTarget, calls *atomic.Int32) int32 {
	t.Helper()
	p := startWindowProbe(target)
	t.Cleanup(p.close)
	deadline := time.Now().Add(10 * probeCooldown)
	for time.Now().Before(deadline) {
		p.loaded()
		time.Sleep(probeCooldown / 3)
	}
	return calls.Load()
}

// R5: a public target (not local) and an SSRF-refused target are permanent
// verdicts: one attempt, never another, however often the window is read.
func TestProbe_PermanentVerdictStopsReprobing_0074(t *testing.T) {
	cases := []struct {
		name       string
		url        string
		ip         string
		allowLocal bool
	}{
		{"not local", "https://gateway.example.com/v1", "93.184.216.34", false},
		{"ssrf refused", "https://lmstudio.test:1234/v1", "127.0.0.1", false},
		{"link-local refused", "http://lmstudio.test:1234/v1", "169.254.169.254", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			shortCooldown(t)
			var calls atomic.Int32
			target := localTarget(c.url, "", countingLookup(net.ParseIP(c.ip), &calls), c.allowLocal)
			if n := attemptsAfterReads(t, target, &calls); n != 1 {
				t.Fatalf("%d probe attempts, want exactly 1: the verdict is permanent", n)
			}
		})
	}
}

// R5: a DNS failure is transient, so the probe keeps retrying lazily.
func TestProbe_TransientFailureIsStillRetried_0074(t *testing.T) {
	shortCooldown(t)
	var calls atomic.Int32
	target := localTarget("http://lmstudio.test:1234/v1", "", countingLookup(nil, &calls), true)
	if n := attemptsAfterReads(t, target, &calls); n < 2 {
		t.Fatalf("%d probe attempts, want a lazy retry after a transient DNS failure", n)
	}
}
