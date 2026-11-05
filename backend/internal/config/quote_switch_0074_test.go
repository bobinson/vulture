package config

// Feature 0074 C16: VULTURE_LLM_QUOTE_VERIFY is normalised to off / observe /
// enforce exactly as the agent normalises it, and the lineage re-anchor gate
// is the agent's conjunction (mode == enforce AND QUOTE_REANCHOR, default on).
// The matrix is a shared fixture so the Python side can pin the same rows.

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"strings"
	"testing"
)

type quoteSwitchCase struct {
	Verify          *string `json:"verify"`
	Reanchor        *string `json:"reanchor"`
	Mode            string  `json:"mode"`
	ReanchorEnabled bool    `json:"reanchor_enabled"`
	Warns           bool    `json:"warns"`
}

func loadQuoteSwitchMatrix(t *testing.T) []quoteSwitchCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/quote_switch_matrix_0074.json")
	if err != nil {
		t.Fatalf("read matrix: %v", err)
	}
	var doc struct {
		Cases []quoteSwitchCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode matrix: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("matrix has no cases")
	}
	return doc.Cases
}

// setOrUnset sets name to *v, or unsets it when v is nil.
func setOrUnset(t *testing.T, name string, v *string) {
	t.Helper()
	val := ""
	if v != nil {
		val = *v
	}
	setEnvFlagCase(t, name, envFlagCase{value: val, unset: v == nil})
}

// captureLog runs fn with the standard logger redirected and returns its output.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(prevFlags) })
	fn()
	return buf.String()
}

func TestQuoteSwitchMatrix_0074(t *testing.T) {
	for _, c := range loadQuoteSwitchMatrix(t) {
		setOrUnset(t, QuoteVerifyEnv, c.Verify)
		setOrUnset(t, QuoteReanchorEnv, c.Reanchor)
		resetWarnedForTest()
		var mode string
		var enabled bool
		out := captureLog(t, func() {
			mode = QuoteVerifyMode()
			enabled = QuoteReanchorEnabled()
		})
		label := describeQuoteCase(c)
		if mode != c.Mode {
			t.Errorf("%s: mode=%q, want %q", label, mode, c.Mode)
		}
		if enabled != c.ReanchorEnabled {
			t.Errorf("%s: reanchor enabled=%v, want %v", label, enabled, c.ReanchorEnabled)
		}
		if warned := strings.Contains(out, QuoteVerifyEnv); warned != c.Warns {
			t.Errorf("%s: warning logged=%v, want %v (log %q)", label, warned, c.Warns, out)
		}
	}
}

func describeQuoteCase(c quoteSwitchCase) string {
	show := func(p *string) string {
		if p == nil {
			return "<unset>"
		}
		return "\"" + *p + "\""
	}
	return "VERIFY=" + show(c.Verify) + " REANCHOR=" + show(c.Reanchor)
}

// The warning is one-time per variable: a mistyped value read on every scan
// must not flood the log.
func TestQuoteVerifyWarningIsOneTime_0074(t *testing.T) {
	t.Setenv(QuoteVerifyEnv, "enforced")
	resetWarnedForTest()
	out := captureLog(t, func() {
		for i := 0; i < 5; i++ {
			QuoteVerifyMode()
		}
	})
	if n := strings.Count(out, QuoteVerifyEnv); n != 1 {
		t.Fatalf("warning logged %d times, want exactly 1 (log %q)", n, out)
	}
}
