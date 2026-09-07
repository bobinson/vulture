package main

import (
	"strings"
	"testing"
)

// Feature 0083 — the three flags parse, and --no-llm implies --no-cache.

func TestNoLLMImpliesNoCache(t *testing.T) {
	f := parseScanFlags([]string{"--no-llm"})
	if !f.noLLM {
		t.Fatal("--no-llm not parsed")
	}
	// The cache is keyed on (source_id, types) and ignores config entirely
	// (audit_service.go GetLatestCompletedAudit). Without this implication a
	// --no-llm scan returns a cached FULL-LLM result and exits — the headline
	// acceptance criterion would be unverifiable.
	if !f.noCache {
		t.Error("--no-llm must imply --no-cache, or a cached LLM result is returned")
	}
}

func TestNoLLMDoesNotDisableTheJudge(t *testing.T) {
	f := parseScanFlags([]string{"--no-llm", "--validate-llm"})
	if !f.noLLM || !f.validateLLM {
		t.Fatalf("both flags must survive together: %+v", f)
	}
	cfg := buildScanConfig(f)
	if cfg["use_llm"] != false {
		t.Errorf("use_llm should be false, got %v", cfg["use_llm"])
	}
	v, ok := cfg["validate"].(map[string]interface{})
	if !ok || v["llm"] != true {
		t.Errorf("validate.llm should survive --no-llm, got %v", cfg["validate"])
	}
}

func TestSizingFlagsParse(t *testing.T) {
	f := parseScanFlags([]string{"--validate-llm", "--validate-llm-top-n", "40", "--validate-llm-batch-size", "3"})
	if f.validateLLMTopN != 40 {
		t.Errorf("top-n = %d, want 40", f.validateLLMTopN)
	}
	if f.validateLLMBatchSize != 3 {
		t.Errorf("batch-size = %d, want 3", f.validateLLMBatchSize)
	}
}

func TestDefaultsAreUnchanged(t *testing.T) {
	f := parseScanFlags(nil)
	if f.noLLM || f.validateLLM || f.tier3 || f.fresh || f.noCache {
		t.Errorf("a bare scan must set no LLM flags: %+v", f)
	}
	if f.validateLLMTopN != 0 || f.validateLLMBatchSize != 0 {
		t.Error("sizing must default to 0 (= unset, emit nothing)")
	}
	// NON-VACUITY: types must be populated, else this test would pass against
	// a parser that returns a zero struct for everything.
	if len(f.types) == 0 {
		t.Fatal("default types empty — parser returned a zero struct")
	}
}

// The new flags must appear in the 0080 unknown-flag message, or the next
// person adding a flag has no list to add to.
func TestGuardMessageListsTheNewFlags(t *testing.T) {
	out, code := runCLIProbe(t, "scan", "--definitely-not-a-flag")
	if code == 0 {
		t.Fatal("non-vacuity: an unknown flag must exit non-zero, or the guard is not running")
	}
	for _, want := range []string{"--no-llm", "--validate-llm-top-n", "--validate-llm-batch-size"} {
		if !strings.Contains(out, want) {
			t.Errorf("guard message omits %s\n%s", want, out)
		}
	}
}

// A bad sizing value must be REFUSED, not silently ignored — the 0080 rule.
func TestSizingFlagsRejectGarbage(t *testing.T) {
	for _, args := range [][]string{
		{"--validate-llm-top-n", "abc"},
		{"--validate-llm-top-n", "0"},
		{"--validate-llm-batch-size", "abc"},
		{"--validate-llm-batch-size", "0"},
	} {
		out, code := runCLIProbe(t, "scan", args...)
		if code == 0 {
			t.Errorf("%v was accepted silently; want a refusal\n%s", args, out)
		}
	}
}
