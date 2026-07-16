package provider

import "strings"

// Model capability predicates (§32.1 #4). Sampling params (temperature/top_p)
// and the token-limit field name are NOT universal: OpenAI o-series reasoning
// models reject temperature≠1 and require max_completion_tokens (not
// max_tokens), and the newest Anthropic models (Opus 4.7/4.8, Sonnet 5, Fable 5)
// removed sampling params entirely. Sending them anyway is a hard 400. These
// predicates gate emission per model so the broker works across the whole
// fleet, not just the models that happen to accept every param.

// oSeriesExact are the OpenAI reasoning-model ids (exact match — a short "o1"
// substring would false-match unrelated ids). Dated snapshots (o3-mini-2025…)
// are caught by the prefix check.
var oSeriesExact = map[string]bool{
	"o1": true, "o1-mini": true, "o1-preview": true,
	"o3": true, "o3-mini": true, "o4-mini": true,
}

var oSeriesPrefixes = []string{"o1-", "o3-", "o4-"}

// anthropicNoSampling are substrings of Anthropic model ids that dropped
// sampling params. Generic aliases (claude-sonnet, claude-3-5-…) still accept
// them, so match only the specific newer versions.
var anthropicNoSampling = []string{
	"opus-4-7", "opus-4.7", "opus-4-8", "opus-4.8",
	"sonnet-5", "sonnet5", "fable-5", "fable5",
}

func isOSeries(model string) bool {
	lm := strings.ToLower(strings.TrimSpace(model))
	if oSeriesExact[lm] {
		return true
	}
	for _, p := range oSeriesPrefixes {
		if strings.HasPrefix(lm, p) {
			return true
		}
	}
	return false
}

// acceptsSamplingParams reports whether the model accepts temperature/top_p.
func acceptsSamplingParams(model string) bool {
	if isOSeries(model) {
		return false
	}
	lm := strings.ToLower(strings.TrimSpace(model))
	for _, s := range anthropicNoSampling {
		if strings.Contains(lm, s) {
			return false
		}
	}
	return true
}

// usesMaxCompletionTokens reports whether the model uses the max_completion_tokens
// field instead of max_tokens (OpenAI o-series).
func usesMaxCompletionTokens(model string) bool {
	return isOSeries(model)
}

// clampTemp constrains t to [lo, hi] — Anthropic caps temperature at [0,1] while
// OpenAI permits up to 2, so a cross-provider value must be clamped per target.
func clampTemp(t, lo, hi float64) float64 {
	if t < lo {
		return lo
	}
	if t > hi {
		return hi
	}
	return t
}
