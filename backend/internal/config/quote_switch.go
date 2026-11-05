package config

import (
	"log"
	"os"
	"strings"
	"sync"
)

// The 0076 quote switches, read by the agents and by the lineage pass. Both
// runtimes normalise them the same way (feature 0074, contract C16), so the
// agent's moved finding and the lineage row's window cannot disagree.
const (
	QuoteVerifyEnv   = "VULTURE_LLM_QUOTE_VERIFY"
	QuoteReanchorEnv = "VULTURE_LLM_QUOTE_REANCHOR"

	QuoteModeOff     = "off"
	QuoteModeObserve = "observe"
	QuoteModeEnforce = "enforce"
)

// warned holds the variable names already reported as unrecognised, so a
// mistyped value read on every scan is logged once per process.
var warned sync.Map

// QuoteVerifyMode is VULTURE_LLM_QUOTE_VERIFY normalised to off / observe /
// enforce: blank is the enforce default, a falsey flag token
// (false/0/no/off) is off, observe/enforce match case-insensitively, and any
// other value is the default with a one-time warning naming the variable.
func QuoteVerifyMode() string {
	raw := os.Getenv(QuoteVerifyEnv)
	v := strings.ToLower(strings.TrimSpace(raw))
	if m, ok := quoteModes[v]; ok {
		return m
	}
	if !ParseFlag(v, true) {
		return QuoteModeOff
	}
	warnUnrecognised(QuoteVerifyEnv, raw)
	return QuoteModeEnforce
}

// quoteModes are the values taken as given; blank is the enforce default.
var quoteModes = map[string]string{
	"": QuoteModeEnforce, QuoteModeObserve: QuoteModeObserve, QuoteModeEnforce: QuoteModeEnforce,
}

// QuoteReanchorEnabled is the line actuator's gate, the agent's conjunction:
// the verifier enforces AND VULTURE_LLM_QUOTE_REANCHOR is on (default on).
func QuoteReanchorEnabled() bool {
	return QuoteVerifyMode() == QuoteModeEnforce && EnvFlag(QuoteReanchorEnv, true)
}

// warnUnrecognised logs, once per variable, that its value was not understood
// and the default applies instead.
func warnUnrecognised(name, value string) {
	if _, dup := warned.LoadOrStore(name, struct{}{}); dup {
		return
	}
	log.Printf("[config] %s=%q is not a recognised value; using the default", name, value)
}

// resetWarnedForTest forgets which variables have been warned about.
func resetWarnedForTest() {
	warned.Range(func(k, _ any) bool { warned.Delete(k); return true })
}
