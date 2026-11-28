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

// The current Claude models are metered at their own list price. Unlisted, they
// fell back to $3/$15: Sonnet 5.5 was over-reported by half (a measured run
// logged $5.11 for $3.41 of spend), while Opus 5.5 ($4/$20) and Fable 5.2
// ($8/$40) were UNDER-reserved, the direction a budget cap cannot tolerate.
func TestActualUSD_CurrentClaudeModels(t *testing.T) {
	cases := map[string][2]float64{
		"claude-sonnet-5-5": {2.00, 10.00},
		"claude-opus-5-5":   {4.00, 20.00},
		"claude-fable-5-2":  {8.00, 40.00},
		// Haiku 5.5 is $0.10/$0.50 up to a 100K-token prompt and $0.50/$2.50
		// above it; one rate per model, so the higher one: never under-reserve.
		"claude-haiku-5-5": {0.50, 2.50},
	}
	for model, rate := range cases {
		want := rate[0] + rate[1] // 1M in + 1M out
		if got := ActualUSD(model, 1_000_000, 1_000_000); got != want {
			t.Errorf("ActualUSD(%s, 1M, 1M) = %.2f, want %.2f", model, got, want)
		}
	}
}
