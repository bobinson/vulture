package provider

import (
	"regexp"
	"strings"
)

// Model capability predicates (§32.1 #4). Sampling params (temperature/top_p)
// and the token-limit field name are NOT universal: OpenAI o-series reasoning
// models reject temperature≠1 and require max_completion_tokens (not
// max_tokens), and every Anthropic model from Opus 4.7 on removed sampling
// params entirely. Sending them anyway is a hard 400. These
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

// claudeLegacySampling matches the Claude models that still accept sampling
// params: every one released before Opus 4.7 (Claude 2 / instant / 3.x, and the
// Claude 4 generation up to 4.6, dated, Bedrock- or Vertex-suffixed or not).
// Every later Claude model answers a non-default temperature/top_p with a 400,
// and so will each new one, so this set is CLOSED: a new model needs no entry.
// (The denylist it replaces had to name each new model and missed Opus 5,
// Opus 5.5 and Haiku 5.5, so the L5 judge's temperature 0.1 400'd on them.)
var claudeLegacySampling = regexp.MustCompile(
	`^claude-(?:2|instant|3)|^claude-(?:opus|sonnet|haiku)-4(?:[-.][0-6])?(?:-\d{8})?(?:-v\d+(?::\d+)?)?(?:@\d{8})?$`)

// claudeModelID returns the Claude model id inside a provider or gateway
// spelling (anthropic/claude-…, anthropic.claude-…), or "" for a model that is
// not Claude.
func claudeModelID(lowerModel string) string {
	i := strings.Index(lowerModel, "claude-")
	if i < 0 {
		return ""
	}
	return lowerModel[i:]
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
	if id := claudeModelID(lm); id != "" {
		return claudeLegacySampling.MatchString(id)
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
