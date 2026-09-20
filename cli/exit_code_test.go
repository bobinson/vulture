package main

import "testing"

// docs/guides/ci_integration.md has always documented three codes:
//
//	0  Audit completed successfully. No findings at or above --exit-on.
//	1  Audit completed. Findings at or above --exit-on were detected.
//	2  Audit execution error: network failure, authentication failure,
//	   LLM error, or server-side fault.
//
// Code 2 was never returned by anything. computeExitCode consulted only
// findings and the --exit-on threshold, never a.Status — so an audit the
// backend had marked `failed` exited 0, and CI went green on a scan that did
// not deliver the coverage it was asked for. Note that BOTH 0 and 1 are
// documented as "Audit completed": returning either for a failed audit
// contradicts the contract in the repository's own docs.
//
// Measured: audit 2de1852f requested {cwe,semgrep}, semgrep never ran, the
// backend correctly recorded `failed` — and `vulture scan` still exited 0.

func TestComputeExitCode_FailedAuditIsAnExecutionError(t *testing.T) {
	a := audit{Status: "failed"}
	if got := computeExitCode(a, ""); got != 2 {
		t.Fatalf("a failed audit must exit 2 (execution error), got %d", got)
	}
}

// --exit-on is a findings-SEVERITY policy. A broken run is not a findings
// question, so the status check must sit BEFORE the `exitOn == ""` early
// return that used to swallow it — otherwise the default invocation, which is
// what most pipelines use, still exits 0.
func TestComputeExitCode_FailedAuditExitsTwoWithoutAnyThreshold(t *testing.T) {
	a := audit{Status: "failed", Findings: []finding{{Severity: "low"}}}
	if got := computeExitCode(a, ""); got != 2 {
		t.Fatalf("a failed audit must exit 2 even with no --exit-on, got %d", got)
	}
}

// The failure dominates the threshold verdict. An incomplete run's finding set
// is not a trustworthy basis for "1 = findings at or above the threshold" —
// the detector that would have raised the decisive finding may be exactly the
// one that never ran. 2 says "do not trust this run", which is the honest
// answer; 1 would assert a completed audit.
func TestComputeExitCode_FailedAuditBeatsAThresholdHit(t *testing.T) {
	a := audit{Status: "failed", Findings: []finding{{Severity: "critical"}}}
	if got := computeExitCode(a, "critical"); got != 2 {
		t.Fatalf("execution error must dominate the findings verdict, got %d", got)
	}
}

func TestComputeExitCode_FailedAuditWithNoFindingsStillExitsTwo(t *testing.T) {
	a := audit{Status: "failed"}
	if got := computeExitCode(a, "critical"); got != 2 {
		t.Fatalf("got %d, want 2", got)
	}
}

// NON-VACUITY. Without these four the tests above would pass against a
// computeExitCode that returned 2 unconditionally.

func TestComputeExitCode_CompletedWithoutThresholdIsSuccess(t *testing.T) {
	a := audit{Status: "completed", Findings: []finding{{Severity: "critical"}}}
	if got := computeExitCode(a, ""); got != 0 {
		t.Fatalf("no --exit-on means findings never fail the build, got %d", got)
	}
}

func TestComputeExitCode_CompletedAboveThresholdIsOne(t *testing.T) {
	a := audit{Status: "completed", Findings: []finding{{Severity: "high"}}}
	if got := computeExitCode(a, "medium"); got != 1 {
		t.Fatalf("a finding at or above the threshold must exit 1, got %d", got)
	}
}

func TestComputeExitCode_CompletedBelowThresholdIsZero(t *testing.T) {
	a := audit{Status: "completed", Findings: []finding{{Severity: "low"}}}
	if got := computeExitCode(a, "high"); got != 0 {
		t.Fatalf("findings below the threshold must exit 0, got %d", got)
	}
}

// An unknown --exit-on value warns and does not fail the build; that existing
// behaviour must survive, but it must not swallow a failed audit either.
func TestComputeExitCode_UnknownThresholdStillReportsAFailedAudit(t *testing.T) {
	if got := computeExitCode(audit{Status: "completed", Findings: []finding{{Severity: "critical"}}}, "bogus"); got != 0 {
		t.Errorf("unknown threshold on a completed audit must not fail the build, got %d", got)
	}
	if got := computeExitCode(audit{Status: "failed"}, "bogus"); got != 2 {
		t.Errorf("unknown threshold must not swallow a failed audit, got %d", got)
	}
}

// A run still in flight is not a failure. Only the terminal `failed` status is.
func TestComputeExitCode_NonTerminalStatusIsNotAnExecutionError(t *testing.T) {
	for _, st := range []string{"", "pending", "running", "completed"} {
		if got := computeExitCode(audit{Status: st}, ""); got != 0 {
			t.Errorf("status %q must not exit 2, got %d", st, got)
		}
	}
}
