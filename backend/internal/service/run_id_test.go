package service

import "testing"

// TestValidateRunID covers both the ACCEPT and REJECT paths of the run_id guard
// (0065 §1.1). Audit finding #6: only the traversal-reject case was tested, so
// an over-tightened regex (rejecting valid ids) would have gone unnoticed.
func TestValidateRunID(t *testing.T) {
	valid := []string{
		"",              // empty = no per-run subdir (allowed)
		"run-42_abc",    // the plan's benign example
		"abc123",
		"A-B_c-9",
		"0",
	}
	for _, id := range valid {
		if err := validateRunID(id); err != nil {
			t.Errorf("validateRunID(%q) = %v, want nil (valid id)", id, err)
		}
	}

	invalid := []string{
		"../etc",
		"../../tmp/escape",
		"a/b",
		"a b",
		"has.dot",
		"semi;colon",
	}
	for _, id := range invalid {
		if err := validateRunID(id); err == nil {
			t.Errorf("validateRunID(%q) = nil, want rejection", id)
		}
	}
}
