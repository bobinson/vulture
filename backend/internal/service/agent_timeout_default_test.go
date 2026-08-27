package service

import (
	"bytes"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Feature 0078 §15.6 / AC15.5 — a guard must fire for the SHIPPED DEFAULTS.
//
// The defect this file pins was not in `timeoutMarginWarning`. That function was
// correct and had seven passing table cases, one of which named 600/900/120 as a
// configuration that MUST warn. The defect was in the WIRING: the call site in
// `NewAgentProxyService` resolved the agent ceiling with a fallback of `0`, and
// the guard returns "" early on `agentMax <= 0`. So for the single most common
// configuration on earth — all three variables unset — the guard was handed the
// vacuous branch and stayed silent about exactly the triple its own unit test
// called unsafe.
//
// The lesson encoded here: a guard's unit tests passing says NOTHING about
// whether the guard is ever handed real inputs. These tests therefore go through
// the real constructor with the environment genuinely unset, and they prove they
// can SEE the pre-fix wiring rather than merely agreeing with the current one.

// unsetTimeoutEnv removes the three timeout variables from the process
// environment for the duration of the test and restores them afterwards.
//
// It deliberately does not use t.Setenv(key, ""): an empty value is not the same
// state as an absent variable, and "the environment is UNSET" is precisely the
// condition AC15.5 is about. os.LookupEnv/os.Unsetenv is the only way to reach
// it. (Consequence: tests using this helper must not call t.Parallel().)
func unsetTimeoutEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"VULTURE_AGENT_PROXY_TIMEOUT_SEC",
		"VULTURE_AGENT_MAX_AUDIT_SECONDS",
		"VULTURE_LLM_CALL_TIMEOUT_SEC",
	} {
		prev, had := os.LookupEnv(key)
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
		t.Cleanup(func() {
			if had {
				_ = os.Setenv(key, prev)
				return
			}
			_ = os.Unsetenv(key)
		})
	}
}

// captureConstructorLog runs the real NewAgentProxyService and returns whatever
// it wrote to the standard logger.
func captureConstructorLog(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags, prevPrefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	})
	_ = NewAgentProxyService(nil)
	return buf.String()
}

// AC15.5: with the environment UNSET, the shipped defaults must produce the
// timeout-margin warning — through the constructor, not through a hand-fed call
// to the pure function.
//
// Shipped defaults are proxy=600, agent ceiling=900 (audit_runner's own
// fallback), llm call=120, so the required proxy ceiling is 1020 > 600. The
// configuration is unsafe as shipped and the operator has to be told.
func TestShippedDefaultsWarnThroughConstructor(t *testing.T) {
	unsetTimeoutEnv(t)

	out := captureConstructorLog(t)

	if !strings.Contains(out, "UNSAFE TIMEOUT MARGIN") {
		t.Fatalf("AC15.5 VIOLATED: with all three timeout variables unset, "+
			"NewAgentProxyService did not warn about the margin. The shipped triple is "+
			"proxy=%d agentMax=%d llmCall=%d, required=%d, so the warning is due. Fix the "+
			"CALL SITE in NewAgentProxyService (agent_proxy_service.go): it must resolve the "+
			"agent ceiling with envAgentMaxAuditSec(), which returns %ds when the variable is "+
			"absent — a fallback of 0 lands on timeoutMarginWarning's vacuous "+
			"`agentMax <= 0` branch and silences the guard. Constructor log was:\n%s",
			defaultAgentProxyTimeoutSec, defaultAgentMaxAuditSec, defaultLLMCallTimeoutSec,
			defaultAgentMaxAuditSec+defaultLLMCallTimeoutSec, defaultAgentMaxAuditSec, out)
	}

	// A warning an operator cannot act on is not much better than silence, so
	// pin the actionable content too: every variable involved, the required
	// minimum, and which variable to raise.
	for _, want := range []string{
		"VULTURE_AGENT_PROXY_TIMEOUT_SEC",
		"VULTURE_AGENT_MAX_AUDIT_SECONDS",
		"VULTURE_LLM_CALL_TIMEOUT_SEC",
		"1020", // 900 + 120, the required proxy ceiling for the shipped defaults
		"Raise VULTURE_AGENT_PROXY_TIMEOUT_SEC to at least 1020",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the shipped-defaults warning must name %q so an operator does not have "+
				"to derive the fix; update the message in timeoutMarginWarning "+
				"(agent_proxy_service.go). Log was:\n%s", want, out)
		}
	}
}

// NON-VACUITY, committed. The test above asserts a warning is present; on its
// own that cannot distinguish "the wiring is correct" from "the assertion is
// unable to fail". This test supplies the deliberately broken input — the
// PRE-FIX resolution, `envDurationSec("VULTURE_AGENT_MAX_AUDIT_SECONDS", 0)` —
// with the environment in exactly the same unset state, and shows that the same
// margin check is SILENT for it.
//
// No repository file is mutated to do this: the broken wiring is reconstructed
// here from the two functions the pre-fix call site used.
func TestTimeoutMarginGuardSeesThePreFixWiring(t *testing.T) {
	unsetTimeoutEnv(t)

	proxy := envDurationSec("VULTURE_AGENT_PROXY_TIMEOUT_SEC", defaultAgentProxyTimeoutSec)
	llmCall := envDurationSec("VULTURE_LLM_CALL_TIMEOUT_SEC", defaultLLMCallTimeoutSec)

	// The pre-fix call site: fallback 0 for an absent agent ceiling.
	preFix := envDurationSec("VULTURE_AGENT_MAX_AUDIT_SECONDS", 0)
	if preFix != 0 {
		t.Fatalf("expected the pre-fix resolution to yield 0 for an unset variable, got %s; "+
			"envDurationSec no longer collapses unset onto its fallback and this "+
			"non-vacuity proof needs rewriting", preFix)
	}
	if w := timeoutMarginWarning(proxy, preFix, llmCall); w != "" {
		t.Fatalf("the pre-fix wiring was expected to be SILENT (that was the defect), "+
			"but produced: %s\nIf timeoutMarginWarning now warns on agentMax<=0 the vacuous "+
			"branch is gone and this proof needs rewriting", w)
	}

	// The shipped wiring, same environment, must not be silent. The two lines
	// together are the proof: TestShippedDefaultsWarnThroughConstructor fails if
	// the call site regresses to the pre-fix form.
	shipped := envAgentMaxAuditSec()
	if w := timeoutMarginWarning(proxy, shipped, llmCall); w == "" {
		t.Fatalf("shipped resolution gave agentMax=%s with proxy=%s llmCall=%s and produced no "+
			"warning; the constructor assertion in this file cannot fail, so it guards "+
			"nothing. Fix envAgentMaxAuditSec / timeoutMarginWarning in agent_proxy_service.go",
			shipped, proxy, llmCall)
	}
}

// checkConstructorWiring returns a human-readable reason the NewAgentProxyService
// body in `body` cannot fire the margin guard for the shipped defaults, or "" when
// the wiring is sound. Split out as a pure function so the guard can be shown to
// FLAG the pre-fix constructor (see the synthetic test below) rather than only
// agreeing with the current one.
func checkConstructorWiring(body string) string {
	ctor := regexp.MustCompile(`(?s)func NewAgentProxyService\(.*?\n}\n`).FindString(body)
	if ctor == "" {
		return "could not locate the NewAgentProxyService body; AC15.5's wiring guard cannot " +
			"verify the call site — update the regexp in this test to the constructor's new shape"
	}
	if !strings.Contains(ctor, "timeoutMarginWarning(") {
		return "NewAgentProxyService no longer calls timeoutMarginWarning: the margin guard is " +
			"unreachable at startup. Restore the call in agent_proxy_service.go, or move it to " +
			"whatever constructor now owns the proxy timeouts and repoint this test"
	}
	if regexp.MustCompile(`envDurationSec\(\s*"VULTURE_AGENT_MAX_AUDIT_SECONDS"`).MatchString(ctor) {
		return "NewAgentProxyService resolves VULTURE_AGENT_MAX_AUDIT_SECONDS with envDurationSec: " +
			"that helper cannot tell unset from 0, and a 0 fallback puts timeoutMarginWarning on " +
			"its vacuous `agentMax <= 0` branch — the exact defect AC15.5 exists to prevent. Use " +
			"envAgentMaxAuditSec() in agent_proxy_service.go"
	}
	if !strings.Contains(ctor, "envAgentMaxAuditSec()") {
		return "NewAgentProxyService must resolve the agent ceiling with envAgentMaxAuditSec(), " +
			"which distinguishes an ABSENT variable (the agent still stops itself at 900s) from " +
			"an explicit 0 (deadline disabled). Change the argument in the timeoutMarginWarning " +
			"call in agent_proxy_service.go"
	}
	return ""
}

// The dynamic reconstruction above is only a faithful stand-in for the pre-fix
// wiring while the real call site keeps using envAgentMaxAuditSec(). This pins
// that statically, so reintroducing the fallback-0 pattern fails HERE with the
// fix named, instead of quietly turning the proof above into a comparison of two
// copies of the same bug.
func TestConstructorResolvesAgentCeilingViaPresenceAwareHelper(t *testing.T) {
	data, err := os.ReadFile("agent_proxy_service.go")
	if err != nil {
		t.Fatalf("read agent_proxy_service.go: %v", err)
	}
	if reason := checkConstructorWiring(string(data)); reason != "" {
		t.Fatalf("AC15.5 wiring violation in agent_proxy_service.go: %s", reason)
	}
}

// NON-VACUITY for the static guard: the pre-fix constructor, as a synthetic
// source string (no repository file is touched), must be flagged. Without this
// a regexp that silently matches nothing would pass forever.
func TestConstructorWiringGuardFlagsThePreFixSource(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			// The actual pre-fix call site.
			name: "fallback of zero for the agent ceiling",
			src: "func NewAgentProxyService(minter BrokerMinter) AgentProxyService {\n" +
				"\tif w := timeoutMarginWarning(auditTimeout,\n" +
				"\t\tenvDurationSec(\"VULTURE_AGENT_MAX_AUDIT_SECONDS\", 0),\n" +
				"\t\tenvDurationSec(\"VULTURE_LLM_CALL_TIMEOUT_SEC\", 120)); w != \"\" {\n" +
				"\t\tlog.Print(w)\n\t}\n\treturn nil\n}\n",
		},
		{
			// A non-zero fallback is still wrong: it cannot represent
			// "explicitly disabled", so AC14.3 and AC15.5 cannot both hold.
			name: "fallback of 900 for the agent ceiling",
			src: "func NewAgentProxyService(minter BrokerMinter) AgentProxyService {\n" +
				"\tif w := timeoutMarginWarning(auditTimeout,\n" +
				"\t\tenvDurationSec(\"VULTURE_AGENT_MAX_AUDIT_SECONDS\", 900),\n" +
				"\t\tenvDurationSec(\"VULTURE_LLM_CALL_TIMEOUT_SEC\", 120)); w != \"\" {\n" +
				"\t\tlog.Print(w)\n\t}\n\treturn nil\n}\n",
		},
		{
			// The guard is never called at all.
			name: "margin check removed from the constructor",
			src: "func NewAgentProxyService(minter BrokerMinter) AgentProxyService {\n" +
				"\tlog.Print(\"[agent-proxy] up\")\n\treturn nil\n}\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if reason := checkConstructorWiring(tc.src); reason == "" {
				t.Fatalf("the wiring guard accepted a constructor that CANNOT warn for the "+
					"shipped defaults, so it guards nothing. Source was:\n%s", tc.src)
			}
		})
	}
}

// Guards the constant the shipped-defaults expectation above is computed from:
// if the defaults ever change to a SAFE triple, AC15.5's "must warn" direction
// is no longer the right assertion and this file must be re-derived rather than
// silently passing (or silently failing) for a new reason.
func TestShippedDefaultTripleIsStillTheUnsafeOne(t *testing.T) {
	required := defaultAgentMaxAuditSec + defaultLLMCallTimeoutSec
	if defaultAgentProxyTimeoutSec >= required {
		t.Fatalf("the shipped defaults are now SAFE (proxy=%d >= %d+%d=%d). AC15.5 asserted the "+
			"warning direction because they were unsafe; re-derive this file to assert SILENCE "+
			"for the defaults, and keep a separate unsafe triple for the non-vacuity proof",
			defaultAgentProxyTimeoutSec, defaultAgentMaxAuditSec, defaultLLMCallTimeoutSec,
			required)
	}
	if required != 1020 {
		t.Fatalf("required minimum is now %d, not 1020; update the literals this file asserts "+
			"in the warning text", required)
	}
}
