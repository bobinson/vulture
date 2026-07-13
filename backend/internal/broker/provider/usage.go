package provider

// Usage-sanity floor (§11): a non-error completion with missing or zero token
// usage is a HARD error — the broker never bills $0 for a served response.

// perTokenUSD is a conservative non-zero unit price applied to reported
// tokens so a metered success never costs $0. Real per-model pricing is a
// pricing-table concern layered above the adapter; this floor guarantees the
// cost is strictly positive whenever tokens were reported.
const perTokenUSD = 0.0000005 // $0.50 / 1M tokens

// normalizeUsage validates the reported wire usage and derives cost. A nil
// usage object or all-zero token counts fail the sanity floor.
func normalizeUsage(w *wireUsage) (Usage, error) {
	if w == nil {
		return Usage{}, ErrUsageMissing
	}
	total := w.PromptTokens + w.CompletionTokens
	if total <= 0 {
		return Usage{}, ErrUsageMissing
	}
	return Usage{
		InputTokens:  w.PromptTokens,
		OutputTokens: w.CompletionTokens,
		CostUSD:      float64(total) * perTokenUSD,
		Estimated:    false,
	}, nil
}
