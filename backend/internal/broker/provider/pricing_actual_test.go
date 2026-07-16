package provider

import (
	"math"
	"testing"
)

// ActualUSD must price reported usage at the model's REAL per-1M rates, not a
// flat placeholder — reconcile charges this into the ledger/budget (§8/§26 C2).
func TestActualUSD_ChargesRealPerModelRate(t *testing.T) {
	// gpt-4o: input $2.50/1M, output $10/1M.
	got := ActualUSD("gpt-4o", 1_000_000, 1_000_000)
	want := 2.50 + 10.00
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("gpt-4o actual cost = %v, want %v (flat-rate regression?)", got, want)
	}
}

// The flat $0.50/1M placeholder would price 1M+1M tokens at $1.00 — the real
// gpt-4o cost is $12.50, a 12.5x under-charge. Guard against its return.
func TestActualUSD_NotFlatPlaceholder(t *testing.T) {
	got := ActualUSD("gpt-4o", 1_000_000, 1_000_000)
	if math.Abs(got-1.00) < 1e-9 {
		t.Fatalf("actual cost is still the flat $0.50/1M placeholder (%v)", got)
	}
}

// Unknown models fall back to the conservative high rate (never under-charge).
func TestActualUSD_UnknownModelUsesFallbackRate(t *testing.T) {
	got := ActualUSD("some-unlisted-model", 1_000_000, 1_000_000)
	want := fallbackInPer1M + fallbackOutPer1M
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("unknown-model cost = %v, want fallback %v", got, want)
	}
}

// normalizeUsage must derive cost from the real model rate, and still enforce
// the usage-sanity floor (zero/nil tokens → hard error).
func TestNormalizeUsage_UsesModelRate(t *testing.T) {
	u, err := normalizeUsage(&wireUsage{PromptTokens: 1_000_000, CompletionTokens: 1_000_000}, "gpt-4o", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if math.Abs(u.CostUSD-12.50) > 1e-9 {
		t.Fatalf("normalizeUsage cost = %v, want 12.50 (real gpt-4o rate)", u.CostUSD)
	}
	// Keyed (billed) provider: the usage floor still holds.
	if _, err := normalizeUsage(nil, "gpt-4o", false); err != ErrUsageMissing {
		t.Fatalf("nil usage: err = %v, want ErrUsageMissing", err)
	}
	if _, err := normalizeUsage(&wireUsage{}, "gpt-4o", false); err != ErrUsageMissing {
		t.Fatalf("zero usage: err = %v, want ErrUsageMissing", err)
	}
}
