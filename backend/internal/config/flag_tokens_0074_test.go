package config

// Feature 0074 re-audit T2 / #16 / #25: the boolean token list is one shared
// fixture (testdata/flag_tokens_0074.json) that the agents' env_flag reads
// too, so a switch both runtimes read cannot mean two things; and an
// unrecognised non-blank value is warned about once, naming the variable.

import (
	"strings"
	"testing"

	"github.com/vulture/backend/internal/config/configtest"
)

func TestEnvFlagMatchesTheSharedTokenList_0074(t *testing.T) {
	for _, c := range configtest.FlagTokens(t) {
		checkFlagTokenCase(t, c, false)
		checkFlagTokenCase(t, c, true)
	}
}

// checkFlagTokenCase reads the case's value under def and checks the verdict
// and whether a warning naming the variable was logged.
func checkFlagTokenCase(t *testing.T, c configtest.FlagToken, def bool) {
	t.Helper()
	const k = "VULTURE_FLAG_TOKENS_TEST"
	t.Setenv(k, c.Value)
	resetWarnedForTest()
	var got bool
	out := captureLog(t, func() { got = EnvFlag(k, def) })
	if got != c.Want(def) {
		t.Errorf("EnvFlag(%q, def=%v) = %v, want %v", c.Value, def, got, c.Want(def))
	}
	if warned := strings.Contains(out, k); warned != c.Warns {
		t.Errorf("EnvFlag(%q): warning logged=%v, want %v (log %q)", c.Value, warned, c.Warns, out)
	}
}

// #16: a mistyped value read on every scan warns once, not on every read.
func TestEnvFlagWarnsOncePerVariable_0074(t *testing.T) {
	const k = "VULTURE_FLAG_TYPO_TEST"
	t.Setenv(k, "flase")
	resetWarnedForTest()
	out := captureLog(t, func() {
		for i := 0; i < 5; i++ {
			EnvFlag(k, true)
		}
	})
	if n := strings.Count(out, k); n != 1 {
		t.Fatalf("warning logged %d times, want exactly 1 (log %q)", n, out)
	}
	if !strings.Contains(out, `"flase"`) {
		t.Errorf("the warning must quote the value it did not understand: %q", out)
	}
}
