package gitutil

import (
	"context"
	"testing"
)

// TestParseOpenSSHVersion pins the banner parser (0065 §L2). Audit finding #4:
// this non-trivial parsing was previously untested, so a banner-format
// regression could silently break the accept-new version gate.
func TestParseOpenSSHVersion(t *testing.T) {
	tests := []struct {
		banner           string
		wantMaj, wantMin int
		wantOK           bool
	}{
		{"OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024", 9, 6, true},
		{"OpenSSH_8.9p1 Ubuntu-3ubuntu0.4, OpenSSL 3.0.2 15 Mar 2022", 8, 9, true},
		{"OpenSSH_7.6p1 Ubuntu-4ubuntu0.7, OpenSSL 1.0.2n  7 Dec 2017", 7, 6, true},
		{"OpenSSH_7.5p1, OpenSSL 1.0.2k-fips", 7, 5, true},
		{"OpenSSH_10.0p2 something", 10, 0, true},
		{"OpenSSH_6.6.1p1 Ubuntu, OpenSSL", 6, 6, true}, // stops at 2nd dot
		{"not an ssh banner", 0, 0, false},
		{"OpenSSH_", 0, 0, false},
		{"OpenSSH_9", 0, 0, false}, // no minor
		{"", 0, 0, false},
	}
	for _, tc := range tests {
		maj, min, ok := parseOpenSSHVersion(tc.banner)
		if ok != tc.wantOK || (ok && (maj != tc.wantMaj || min != tc.wantMin)) {
			t.Errorf("parseOpenSSHVersion(%q) = (%d,%d,%v), want (%d,%d,%v)",
				tc.banner, maj, min, ok, tc.wantMaj, tc.wantMin, tc.wantOK)
		}
	}
}

// TestEnsureSSHStrictCompat_EnvBranches covers the two decision branches that do
// not require probing a real ssh binary: the insecure-rollback flag and an
// explicit non-accept-new strict mode both short-circuit to "" (no adjustment).
func TestEnsureSSHStrictCompat_EnvBranches(t *testing.T) {
	ctx := context.Background()
	noopSetenv := func(string, string) error { return nil }

	t.Run("insecure rollback flag → no adjustment", func(t *testing.T) {
		t.Setenv("VULTURE_GIT_SSH_INSECURE", "true")
		t.Setenv("VULTURE_GIT_SSH_STRICT", "")
		if w := EnsureSSHStrictCompat(ctx, noopSetenv); w != "" {
			t.Fatalf("insecure flag should skip the gate, got warning %q", w)
		}
	})

	t.Run("explicit non-accept-new strict mode is respected", func(t *testing.T) {
		t.Setenv("VULTURE_GIT_SSH_INSECURE", "")
		t.Setenv("VULTURE_GIT_SSH_STRICT", "yes")
		if w := EnsureSSHStrictCompat(ctx, noopSetenv); w != "" {
			t.Fatalf("explicit strict=yes should be respected (no probe/adjust), got %q", w)
		}
	})
}
