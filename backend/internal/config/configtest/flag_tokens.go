// Package configtest holds test-only helpers shared by the packages that read
// a boolean switch, so each pins the same fixture without its own decoder.
package configtest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// FlagToken is one row of testdata/flag_tokens_0074.json (feature 0074
// re-audit T2): the value, its verdict (nil = not a token, the caller's
// default applies) and whether an unrecognised value is warned about.
type FlagToken struct {
	Value   string `json:"value"`
	Verdict *bool  `json:"-"`
	Warns   bool   `json:"warns"`
}

// Want is the row's verdict under default def.
func (c FlagToken) Want(def bool) bool {
	if c.Verdict == nil {
		return def
	}
	return *c.Verdict
}

// FlagTokens loads the shared token fixture, the one the Python agents'
// env_flag is held to as well.
func FlagTokens(tb testing.TB) []FlagToken {
	tb.Helper()
	raw, err := os.ReadFile(fixturePath())
	if err != nil {
		tb.Fatalf("read shared token fixture: %v", err)
	}
	out, err := decodeFlagTokens(raw)
	if err != nil || len(out) == 0 {
		tb.Fatalf("decode shared token fixture: %v", err)
	}
	return out
}

func decodeFlagTokens(raw []byte) ([]FlagToken, error) {
	var doc struct {
		Cases []struct {
			FlagToken
			Verdict json.RawMessage `json:"verdict"`
		} `json:"cases"`
	}
	err := json.Unmarshal(raw, &doc)
	out := make([]FlagToken, 0, len(doc.Cases))
	for _, c := range doc.Cases {
		out = append(out, withVerdict(c.FlagToken, c.Verdict))
	}
	return out, err
}

// withVerdict sets the row's verdict: true / false, anything else nil.
func withVerdict(c FlagToken, raw json.RawMessage) FlagToken {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		c.Verdict = &b
	}
	return c
}

// fixturePath locates the fixture beside this package, from any test's cwd.
func fixturePath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "testdata", "flag_tokens_0074.json")
}
