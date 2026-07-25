package provider

// Usage-sanity floor (§11): a non-error completion with missing or zero token
// usage is a HARD error — the broker never bills $0 for a served response.

// normalizeUsage validates the reported wire usage and derives the ACTUAL
// cost at the model's real per-1M rates (§26 C2).
//
// §32.1 #5: the usage-sanity floor (never bill $0 for a served response) applies
// only to BILLED cloud providers (keyed). Resolution order:
//   - prompt+completion reported → real usage.
//   - only total_tokens reported → attribute to input, mark Estimated (some
//     OpenAI-compat backends report only the aggregate).
//   - none reported + KEYLESS (local $0 endpoint) → Estimated zero-cost, NOT an
//     error (a valid completion must not be dropped over a missing meter).
//   - none reported + KEYED → ErrUsageMissing (the billing floor holds).
func normalizeUsage(w *wireUsage, model string, keyless bool) (Usage, error) {
	if w != nil && w.PromptTokens+w.CompletionTokens > 0 {
		return Usage{
			InputTokens:  w.PromptTokens,
			OutputTokens: w.CompletionTokens,
			CostUSD:      ActualUSD(model, w.PromptTokens, w.CompletionTokens),
			Estimated:    false,
		}, nil
	}
	if w != nil && w.TotalTokens > 0 {
		return Usage{
			InputTokens: w.TotalTokens,
			CostUSD:     ActualUSD(model, w.TotalTokens, 0),
			Estimated:   true,
		}, nil
	}
	if keyless {
		return Usage{Estimated: true}, nil
	}
	return Usage{}, ErrUsageMissing
}
