package service

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The pure guard `timeoutMarginWarning` is correct and covered by
// agent_timeout_margin_test.go, which names 600/900/120 as a case that MUST
// warn ("shipped defaults are flagged"). The WIRING must therefore show the
// guard that same triple when nothing is configured, because 900 is what the
// agent actually uses: audit_runner resolves
// `_safe_int_env("VULTURE_AGENT_MAX_AUDIT_SECONDS", 900)`.
//
// Passing 0 as the fallback instead lands on the guard's `agentMax <= 0`
// vacuous branch, so the single most common configuration on earth — all three
// vars unset — was silently declared safe while the real triple is
// 600 / 900 / 120, required 1020 > 600.
//
// The distinction that makes this fixable without breaking AC14.3 is presence:
// `envDurationSec` cannot tell an explicit `0` from an unset var, and
// AC14.3 needs `VULTURE_AGENT_MAX_AUDIT_SECONDS=0` (deadline deliberately
// disabled) to stay silent.
func TestEnvAgentMaxAuditSecMirrorsAgentSideResolution(t *testing.T) {
	cases := []struct {
		name string
		set  bool
		val  string
		want time.Duration
	}{
		{
			// The shipped default. audit_runner.py's own fallback is 900, so an
			// unset var does NOT mean "no agent deadline".
			name: "unset mirrors the agent-side default of 900",
			want: 900 * time.Second,
		},
		{
			// AC14.3: the agent treats an explicit 0 as "no deadline"
			// (`if _max_audit_s > 0`), so the backend must too.
			name: "explicit zero disables the deadline",
			set:  true, val: "0", want: 0,
		},
		{
			name: "explicit negative disables the deadline",
			set:  true, val: "-1", want: 0,
		},
		{
			name: "explicit positive is honoured",
			set:  true, val: "7200", want: 7200 * time.Second,
		},
		{
			// _safe_int_env logs and uses the default on an unparseable value.
			name: "unparseable falls back to the agent-side default",
			set:  true, val: "later", want: 900 * time.Second,
		},
		{
			// Same .env-quoting tolerance envDurationSec already has.
			name: "inline comment is tolerated",
			set:  true, val: "7200 # 2h", want: 7200 * time.Second,
		},
		{
			name: "empty string is treated as unset",
			set:  true, val: "", want: 900 * time.Second,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("VULTURE_AGENT_MAX_AUDIT_SECONDS", tc.val)
			} else {
				t.Setenv("VULTURE_AGENT_MAX_AUDIT_SECONDS", "")
			}
			if got := envAgentMaxAuditSec(); got != tc.want {
				t.Fatalf("envAgentMaxAuditSec() = %s, want %s", got, tc.want)
			}
		})
	}
}

// AC14.1 end to end: the guard must actually FIRE for the shipped-default
// configuration, not merely be capable of firing when handed the triple by a
// test.
func TestNewAgentProxyServiceWarnsForShippedDefaults(t *testing.T) {
	cases := []struct {
		name                     string
		proxy, agentMax, llmCall string
		wantWarn                 bool
		wantRequired             string
	}{
		{
			// Nothing configured: Mode E / bare dev. 600 / 900 / 120 -> 1020.
			name:     "all unset is unsafe and says so",
			wantWarn: true, wantRequired: "1020",
		},
		{
			// AC14.3 — an operator who explicitly disabled the agent deadline
			// must not be nagged.
			name:     "explicit agent max of zero is silent",
			agentMax: "0", wantWarn: false,
		},
		{
			// AC14.2 — docker-compose's backend block (1200 / 900 / 120).
			name:  "compose defaults are safe",
			proxy: "1200", agentMax: "900", llmCall: "120", wantWarn: false,
		},
		{
			// The measured 3c168626 configuration, reached through the wiring.
			name:  "measured unsafe config warns with its required minimum",
			proxy: "7500", agentMax: "7200", llmCall: "600",
			wantWarn: true, wantRequired: "7800",
		},
		{
			// The sample native_installation.md advertised: 7500/7200/600 is
			// unsafe, 7800 is the fix.
			name:  "corrected native sample is safe",
			proxy: "7800", agentMax: "7200", llmCall: "600", wantWarn: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VULTURE_AGENT_PROXY_TIMEOUT_SEC", tc.proxy)
			t.Setenv("VULTURE_AGENT_MAX_AUDIT_SECONDS", tc.agentMax)
			t.Setenv("VULTURE_LLM_CALL_TIMEOUT_SEC", tc.llmCall)

			var buf bytes.Buffer
			prevOut, prevFlags, prevPrefix := log.Writer(), log.Flags(), log.Prefix()
			log.SetOutput(&buf)
			log.SetFlags(0)
			defer func() {
				log.SetOutput(prevOut)
				log.SetFlags(prevFlags)
				log.SetPrefix(prevPrefix)
			}()

			_ = NewAgentProxyService(nil)
			out := buf.String()

			warned := strings.Contains(out, "UNSAFE TIMEOUT MARGIN")
			if tc.wantWarn && !warned {
				t.Fatalf("expected an unsafe-margin warning for proxy=%q agentMax=%q llmCall=%q, log was:\n%s",
					tc.proxy, tc.agentMax, tc.llmCall, out)
			}
			if !tc.wantWarn && warned {
				t.Fatalf("unexpected unsafe-margin warning for proxy=%q agentMax=%q llmCall=%q:\n%s",
					tc.proxy, tc.agentMax, tc.llmCall, out)
			}
			if tc.wantRequired != "" && !strings.Contains(out, tc.wantRequired) {
				t.Fatalf("warning should name the required minimum %s, log was:\n%s", tc.wantRequired, out)
			}
		})
	}
}

// The whole defect was a mirrored constant with nothing checking the mirror:
// `defaultLLMCallTimeoutSec` was copied from the agent and `900` was not, and no
// test noticed. This guard reads the agent's own resolution site so the next
// divergence fails here instead of at 2am in a truncated run.
func TestMirroredAgentDefaultsMatchAuditRunner(t *testing.T) {
	path := filepath.Join("..", "..", "..", "agents", "shared", "shared", "audit_runner.py")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	body := string(data)

	cases := []struct {
		envVar   string
		mirrored int
	}{
		{"VULTURE_AGENT_MAX_AUDIT_SECONDS", defaultAgentMaxAuditSec},
		{"VULTURE_LLM_CALL_TIMEOUT_SEC", defaultLLMCallTimeoutSec},
	}
	for _, tc := range cases {
		t.Run(tc.envVar, func(t *testing.T) {
			re := regexp.MustCompile(
				`_safe_int_env\(\s*"` + regexp.QuoteMeta(tc.envVar) + `"\s*,\s*(\d+)\s*\)`)
			m := re.FindStringSubmatch(body)
			if m == nil {
				t.Fatalf("audit_runner.py no longer resolves %s via _safe_int_env with a "+
					"literal default; the backend mirror of it cannot be verified", tc.envVar)
			}
			agentDefault, err := strconv.Atoi(m[1])
			if err != nil {
				t.Fatalf("unparseable agent default %q for %s", m[1], tc.envVar)
			}
			if agentDefault != tc.mirrored {
				t.Fatalf("agent default for %s is %d but the backend mirrors %d — the margin "+
					"check would compare values that are not in force",
					tc.envVar, agentDefault, tc.mirrored)
			}
		})
	}
}
