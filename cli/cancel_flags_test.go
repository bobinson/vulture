package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Feature 0080 CLI contract. Two defects from one real report:
//
//   vulture scan ~/src/togetherapp/ --staging-url http://... \
//     --max-iterations 1233000000 --no-cache --allow-local \
//     --types ...,semgrep --plugins semgrep
//
// FOUR of those flags were silently discarded, and Ctrl-C left a 71-minute run
// going with no id to act on.

// helpProbe re-executes this test binary as a subprocess so fatalf's os.Exit
// can be observed. fatalf is the CLI's own exit path; asserting on it any other
// way would test a stub instead of the behaviour.
func runCLIProbe(t *testing.T, name string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestFlagProbeSubprocess")
	cmd.Env = append(os.Environ(), "CLI_PROBE="+name, "CLI_PROBE_ARGS="+strings.Join(args, "\x1f"))
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	return string(out), code
}

func TestFlagProbeSubprocess(t *testing.T) {
	name := os.Getenv("CLI_PROBE")
	if name == "" {
		t.Skip("not the subprocess")
	}
	var args []string
	if raw := os.Getenv("CLI_PROBE_ARGS"); raw != "" {
		args = strings.Split(raw, "\x1f")
	}
	switch name {
	case "scan":
		parseScanFlags(args)
	case "cancel":
		parseCancelFlags(args)
	}
}

// The four flags from the report must each be REFUSED, not ignored.
func TestScanRejectsFlagsItDoesNotImplement(t *testing.T) {
	for _, flag := range []string{
		"--staging-url", "--max-iterations", "--allow-local", "--plugins",
	} {
		t.Run(flag, func(t *testing.T) {
			out, code := runCLIProbe(t, "scan", flag, "value")
			if code == 0 {
				t.Fatalf("%s was accepted silently; it must be refused", flag)
			}
			if !strings.Contains(out, "unknown flag") {
				t.Errorf("expected an 'unknown flag' message for %s, got: %s", flag, out)
			}
		})
	}
}

// The error must point somewhere useful, not just say no.
func TestUnknownFlagErrorNamesTheAlternative(t *testing.T) {
	out, _ := runCLIProbe(t, "scan", "--max-iterations", "5")
	for _, want := range []string{"vulture prove", "--types"} {
		if !strings.Contains(out, want) {
			t.Errorf("the unknown-flag message should mention %q; got: %s", want, out)
		}
	}
	out, _ = runCLIProbe(t, "scan", "--plugins", "semgrep")
	if !strings.Contains(out, "VULTURE_PLUGINS") {
		t.Errorf("--plugins should point at the server-side env var; got: %s", out)
	}
}

// Every flag scan DOES implement must still be accepted — a strict parser that
// rejects real flags is worse than a lax one.
func TestScanStillAcceptsItsOwnFlags(t *testing.T) {
	ok := [][]string{
		{"--types", "cwe,xss"},
		{"--no-cache"},
		{"--fresh"},
		{"--llm-tier3"},
		{"--validate-llm"},
		{"--validate-llm-top-n", "5"},
		{"--api-key", "k"},
		{"--server", "http://x"},
		{"--types", "cwe", "--no-cache", "--fresh", "--validate-llm"},
	}
	for _, args := range ok {
		if _, code := runCLIProbe(t, "scan", args...); code != 0 {
			t.Errorf("scan rejected its own flags %v", args)
		}
	}
}

// A bare positional (not a flag) must not trip the strict check.
func TestScanIgnoresNonFlagPositionals(t *testing.T) {
	if _, code := runCLIProbe(t, "scan", "somevalue"); code != 0 {
		t.Error("a non-flag positional must not be treated as an unknown flag")
	}
}

func TestCancelRejectsUnknownFlags(t *testing.T) {
	if _, code := runCLIProbe(t, "cancel", "--nope"); code == 0 {
		t.Error("cancel accepted an unknown flag")
	}
	if _, code := runCLIProbe(t, "cancel", "--api-key", "k"); code != 0 {
		t.Error("cancel rejected a CI flag it should share")
	}
}
