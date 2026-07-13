package provider

// Usage-sanity floor (§11): a non-error completion with missing or zero token
// usage is a HARD error — the broker never bills $0 for a served response.

// normalizeUsage validates the reported wire usage and derives the ACTUAL
// cost at the model's real per-1M rates (§26 C2). A nil usage object or
// all-zero token counts fail the sanity floor.
func normalizeUsage(w *wireUsage, model string) (Usage, error) {
	if w == nil {
		return Usage{}, ErrUsageMissing
	}
	if w.PromptTokens+w.CompletionTokens <= 0 {
		return Usage{}, ErrUsageMissing
	}
	return Usage{
		InputTokens:  w.PromptTokens,
		OutputTokens: w.CompletionTokens,
		CostUSD:      ActualUSD(model, w.PromptTokens, w.CompletionTokens),
		Estimated:    false,
	}, nil
}
