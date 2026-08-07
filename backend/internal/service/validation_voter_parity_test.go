package service

// Cross-language voter parity — the Go half.
//
// Both voters consume testdata/voter_parity_cases.json and must produce
// identical (status, confidence). The Python half is
// agents/shared/tests/unit/validate/test_voter_parity.py and reads THIS file,
// so the fixture has exactly one home.
//
// Feature 0072 created this. Before it, both voter headers described a parity
// test and the Python header claimed CI enforced it; neither the fixture nor
// either test existed, so the two implementations could drift silently — which
// matters more now that a check's `result` carries gate semantics.

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

type parityCheck struct {
	ID     string  `json:"id"`
	Weight float64 `json:"weight"`
	Result string  `json:"result"`
}

type parityWant struct {
	Status     string  `json:"status"`
	Confidence float64 `json:"confidence"`
}

type parityCase struct {
	Name   string        `json:"name"`
	Checks []parityCheck `json:"checks"`
	Want   parityWant    `json:"want"`
}

type parityFixture struct {
	Cases []parityCase `json:"cases"`
}

const parityFixturePath = "testdata/voter_parity_cases.json"

func loadParityFixture(t *testing.T) parityFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(parityFixturePath))
	if err != nil {
		t.Fatalf("read parity fixture: %v", err)
	}
	var fx parityFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse parity fixture: %v", err)
	}
	if len(fx.Cases) == 0 {
		t.Fatal("parity fixture has no cases")
	}
	return fx
}

func TestVoterParityFixture(t *testing.T) {
	fx := loadParityFixture(t)
	for _, c := range fx.Cases {
		t.Run(c.Name, func(t *testing.T) {
			checks := make([]VoterCheck, 0, len(c.Checks))
			for _, pc := range c.Checks {
				checks = append(checks, VoterCheck{
					ID: pc.ID, Weight: pc.Weight, Result: pc.Result,
				})
			}
			got := Vote(checks)
			if got.Status != c.Want.Status {
				t.Errorf("status: got %q, want %q", got.Status, c.Want.Status)
			}
			if math.Abs(got.Confidence-c.Want.Confidence) > 1e-9 {
				t.Errorf("confidence: got %v, want %v", got.Confidence, c.Want.Confidence)
			}
		})
	}
}

// TestVoterParityLiteralsPinned guards the constants themselves. The obligation
// state and judge admissibility travel across a process boundary as bare
// strings; if Go and Python drift on a literal the gate silently disables with
// no behavioural test failing, because each side stays self-consistent.
func TestVoterParityLiteralsPinned(t *testing.T) {
	for _, tc := range []struct{ got, want string }{
		{ObligationID, "obligation"},
		{ObligationUnknown, "unknown"},
		{ObligationDischarged, "discharged"},
		{ObligationRefuted, "refuted"},
		{JudgeCited, "real_bug"},
		{JudgeUncited, "real_bug_uncited"},
		{JudgeUndecided, "undecided"},
	} {
		if tc.got != tc.want {
			t.Errorf("literal drift: got %q, want %q", tc.got, tc.want)
		}
	}
	if _, ok := AuthoritativePositiveIDs["memory"]; !ok {
		t.Error("AuthoritativePositiveIDs must contain \"memory\"")
	}
	if _, ok := AuthoritativeCheckIDs["suppression"]; !ok {
		t.Error("AuthoritativeCheckIDs must contain \"suppression\"")
	}
}

// TestVoterParityCoversTheGateBranches fails when a 0072 branch loses its
// fixture coverage — the fixture is the contract, so a rule added to either
// voter without a case here is exactly the drift this file exists to catch.
func TestVoterParityCoversTheGateBranches(t *testing.T) {
	fx := loadParityFixture(t)
	seen := map[string]bool{}
	for _, c := range fx.Cases {
		for _, pc := range c.Checks {
			switch {
			case pc.ID == ObligationID:
				seen["obligation:"+pc.Result] = true
			case pc.ID == "llm_judge" && pc.Weight >= 0:
				seen["judge:"+pc.Result] = true
			case pc.ID == "memory":
				if pc.Weight > 0 {
					seen["memory:positive"] = true
				} else {
					seen["memory:negative"] = true
				}
			}
		}
	}
	for _, required := range []string{
		"obligation:unknown", "obligation:discharged", "obligation:refuted",
		"judge:real_bug", "judge:real_bug_uncited",
		"memory:positive", "memory:negative",
	} {
		if !seen[required] {
			t.Errorf("parity fixture has no case exercising %s", required)
		}
	}
}
