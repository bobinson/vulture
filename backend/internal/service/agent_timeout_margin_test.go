package service

import (
	"strings"
	"testing"
	"time"
)

// The documented invariant was "PROXY_TIMEOUT >= AGENT_MAX_AUDIT_SECONDS", and
// it is INSUFFICIENT. The agent checks its own whole-audit deadline BETWEEN
// LLM batches, so it can overshoot that deadline by up to one full
// VULTURE_LLM_CALL_TIMEOUT_SEC before it next looks.
//
// Measured on audit 3c168626: proxy=7500, agent=7200, call=600. The invariant
// held (7500 >= 7200) yet the agent could reach 7800s, and the backend closed
// the connection at exactly 2h5m with chaos at batch 26/27, cwe 25/27, soc2
// 25/27, xss 23/26 — each logging `audit_cancelled reason=stream_closed`. They
// never emitted a result snapshot, so 309 findings were rescued from the
// provenance-less delta path.
//
// The correct invariant is:
//     PROXY >= AGENT_MAX + LLM_CALL_TIMEOUT
func TestTimeoutMarginInvariant(t *testing.T) {
	cases := []struct {
		name                     string
		proxy, agentMax, llmCall time.Duration
		wantWarn                 bool
	}{
		{
			// The measured configuration. Satisfies the OLD invariant, and is
			// exactly the one that truncated four agents.
			name: "measured 3c168626 config is unsafe",
			proxy: 7500 * time.Second, agentMax: 7200 * time.Second,
			llmCall: 600 * time.Second, wantWarn: true,
		},
		{
			name: "margin exactly equal to one call is safe",
			proxy: 7800 * time.Second, agentMax: 7200 * time.Second,
			llmCall: 600 * time.Second, wantWarn: false,
		},
		{
			name: "generous margin is safe",
			proxy: 9000 * time.Second, agentMax: 7200 * time.Second,
			llmCall: 600 * time.Second, wantWarn: false,
		},
		{
			name: "proxy below agent max is unsafe under either invariant",
			proxy: 600 * time.Second, agentMax: 900 * time.Second,
			llmCall: 120 * time.Second, wantWarn: true,
		},
		{
			// Defaults as shipped: 600 / 900 / 120.
			name: "shipped defaults are flagged",
			proxy: 600 * time.Second, agentMax: 900 * time.Second,
			llmCall: 120 * time.Second, wantWarn: true,
		},
		{
			name: "agent deadline disabled means no constraint",
			proxy: 600 * time.Second, agentMax: 0,
			llmCall: 120 * time.Second, wantWarn: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := timeoutMarginWarning(tc.proxy, tc.agentMax, tc.llmCall)
			if tc.wantWarn && got == "" {
				t.Fatalf("expected a warning for proxy=%s agent=%s call=%s, got none",
					tc.proxy, tc.agentMax, tc.llmCall)
			}
			if !tc.wantWarn && got != "" {
				t.Fatalf("unexpected warning: %s", got)
			}
			if tc.wantWarn && !strings.Contains(got, "VULTURE_AGENT_PROXY_TIMEOUT_SEC") {
				t.Fatalf("warning must name the knob to change, got: %s", got)
			}
		})
	}
}

// The warning has to state the REQUIRED value, not merely that something is
// wrong: an operator reading it at 2am should not have to derive the sum.
func TestWarningStatesTheRequiredValue(t *testing.T) {
	got := timeoutMarginWarning(7500*time.Second, 7200*time.Second, 600*time.Second)
	if !strings.Contains(got, "7800") {
		t.Fatalf("warning should name the required minimum 7800, got: %s", got)
	}
}
