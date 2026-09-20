package model

import "testing"

func TestFindingLineage_FormatRef(t *testing.T) {
	cases := []struct {
		name      string
		refNumber int
		expected  string
	}{
		{"zero returns empty", 0, ""},
		{"negative returns empty", -1, ""},
		{"one", 1, "VLT-0001"},
		{"forty two", 42, "VLT-0042"},
		{"four digits", 9999, "VLT-9999"},
		{"five digits", 10000, "VLT-10000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &FindingLineage{RefNumber: tc.refNumber}
			got := l.FormatRef()
			if got != tc.expected {
				t.Errorf("FormatRef() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestActiveLineageStatuses(t *testing.T) {
	got := ActiveLineageStatuses()
	// `unconfirmed` joins the set in feature 0091. It is deliberately ACTIVE:
	// it means the scan could not DECIDE the row (lost quote, unreadable file,
	// verifier exception), and a terminal "unconfirmed" would be a slower
	// version of the silent disappearance the feature exists to end. The next
	// scan must still be allowed to act on it.
	want := []LineageStatus{
		LineageStatusOpen, LineageStatusInProgress,
		LineageStatusRegression, LineageStatusUnconfirmed,
	}
	if len(got) != len(want) {
		t.Fatalf("ActiveLineageStatuses() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ActiveLineageStatuses()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestActiveLineageStatusesExcludesTerminals pins the half that decides whether
// a scan may overwrite a human decision: the user-set terminals and the
// scanner-set one must never be "active".
func TestActiveLineageStatusesExcludesTerminals(t *testing.T) {
	for _, s := range []LineageStatus{
		LineageStatusResolved, LineageStatusAcceptedRisk,
		LineageStatusFalsePositive, LineageStatusFixed,
	} {
		for _, active := range ActiveLineageStatuses() {
			if active == s {
				t.Fatalf("terminal status %q must not be active", s)
			}
		}
	}
}

// TestActiveLineageStatusesReturnsAFreshSlice guards the single-definition
// rule: a caller that mutates the result must not corrupt the next caller's.
func TestActiveLineageStatusesReturnsAFreshSlice(t *testing.T) {
	first := ActiveLineageStatuses()
	first[0] = LineageStatusFixed
	if ActiveLineageStatuses()[0] != LineageStatusOpen {
		t.Fatal("ActiveLineageStatuses() shares backing storage between calls")
	}
}

// TestTierOf pins the tier rule (feature 0091 §5.1). It is the single fact
// that decides whether a lineage row closes on absence or only on evidence,
// so every provenance family that exists in the store is enumerated here.
func TestTierOf(t *testing.T) {
	for _, tc := range []struct {
		provenance string
		want       string
	}{
		{"llm", TierLLM},
		{"llm_l5_verified", TierLLM},
		{"llm_tier3", TierLLM},
		{"LLM_L5_VERIFIED", TierLLM}, // case is not identity
		{"  llm_generated  ", TierLLM},
		{"skill", TierDeterministic},
		{"catalog_rollup", TierDeterministic},
		{"signature_trusted", TierDeterministic},
		{"plugin:semgrep", TierDeterministic},
		// 5,750 persisted findings carry no provenance at all: they predate
		// the field. They must read as deterministic, because that is exactly
		// the closure rule they have always had — defaulting them to the LLM
		// tier would freeze every one of them at `unconfirmed`.
		{"", TierDeterministic},
		{"   ", TierDeterministic},
	} {
		if got := TierOf(tc.provenance); got != tc.want {
			t.Errorf("TierOf(%q) = %q, want %q", tc.provenance, got, tc.want)
		}
	}
}

// TestMemoryStatusForLineage pins the §8 mapping. The load-bearing rows are
// the two that do NOT map to "open": `fixed` must leave the prior-findings
// block (or the finding can never be re-reported and never regress), and the
// dismissals must NOT (or the model re-reports something a human rejected).
func TestMemoryStatusForLineage(t *testing.T) {
	for _, tc := range []struct {
		status LineageStatus
		want   string
	}{
		{LineageStatusOpen, "open"},
		{LineageStatusInProgress, "open"},
		{LineageStatusRegression, "open"},
		{LineageStatusUnconfirmed, "open"},
		{LineageStatusFixed, "resolved"},
		{LineageStatusResolved, "resolved"},
		{LineageStatusFalsePositive, "false_positive"},
		{LineageStatusAcceptedRisk, "accepted_risk"},
	} {
		if got := MemoryStatusForLineage(tc.status); got != tc.want {
			t.Errorf("MemoryStatusForLineage(%q) = %q, want %q", tc.status, got, tc.want)
		}
	}
}

// TestHasEvidenceProtocol pins the version gate that decides whether an
// agent's silence may close anything: absent or < 2 means OLD AGENT.
func TestHasEvidenceProtocol(t *testing.T) {
	var nilResult *ScanResult
	if nilResult.HasEvidenceProtocol() {
		t.Fatal("a missing result must not be treated as evidence-capable")
	}
	if (&ScanResult{}).HasEvidenceProtocol() {
		t.Fatal("result_schema absent means schema 1, i.e. an old agent")
	}
	if (&ScanResult{ResultSchema: 1}).HasEvidenceProtocol() {
		t.Fatal("result_schema 1 is an old agent")
	}
	if !(&ScanResult{ResultSchema: 2}).HasEvidenceProtocol() {
		t.Fatal("result_schema 2 speaks the 0091 protocol")
	}
	if !(&ScanResult{ResultSchema: 3}).HasEvidenceProtocol() {
		t.Fatal("a FUTURE schema must not read as an old agent")
	}
}
