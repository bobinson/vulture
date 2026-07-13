package provider

// Pricing (feature 0064, §8). A conservative MAX-price reservation estimate so
// the budget CAS actually enforces the per-tenant cap BEFORE the provider call.
// Mirrors agents/shared/shared/llm/provider.py COST_PER_1M_TOKENS; a follow-up
// sources this from the provider_config table instead of a compiled map.

// priceUSDPer1M maps a model to (input, output) USD per 1M tokens.
var priceUSDPer1M = map[string][2]float64{
	"gpt-4o":        {2.50, 10.00},
	"claude-sonnet": {3.00, 15.00},
	"gemini-pro":    {1.25, 5.00},
}

const (
	defaultMaxTokens   = 4096
	defaultInputBudget = 8000  // conservative input-token allowance for the reserve
	fallbackInPer1M    = 3.00  // unknown model -> reserve at a high known rate
	fallbackOutPer1M   = 15.00 // (never under-reserve for an unpriced model)
)

// EstimateUSD returns a positive, conservative reservation estimate for one
// call: (input allowance x in-rate) + (maxTokens x out-rate), per 1M tokens.
// It NEVER returns 0 for a real call, so the CAS cap is enforced pre-flight.
func EstimateUSD(model string, maxTokens int) float64 {
	if maxTokens <= 0 {
		maxTokens = defaultMaxTokens
	}
	in, out := fallbackInPer1M, fallbackOutPer1M
	if p, ok := priceUSDPer1M[model]; ok {
		in, out = p[0], p[1]
	}
	return (float64(defaultInputBudget)*in + float64(maxTokens)*out) / 1_000_000
}
