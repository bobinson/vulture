// Package modelmeta is the broker-owned model context-window registry (feature
// 0064 §31). The broker resolves the run model's context window here and injects
// it at dispatch so the agent sizes its LLM phase without a hand-maintained
// per-agent table. Mirrors the Python source-of-truth tables
// (agents/shared/shared/llm/provider.py CONTEXT_WINDOWS / _MODEL_FAMILY_CTX) —
// keep the two in sync (same Python-parity contract as provider/pricing.go),
// extended with the modern families the Python set was missing (glm/gemini/
// gemma-3), whose absence made a custom-gateway model fall to the timid default.
package modelmeta

import (
	"strconv"
	"strings"
)

// DefaultContextWindow is the window (tokens) for an unknown model (§31). Raised
// from the old 8,192 custom-endpoint fallback and unified with the Python
// default. Rationale: overshoot → hard provider error → skills-only (recoverable
// + hinted); undershoot → merely fewer files/call (safe). Nearly all current
// mainstream models are ≥32K, and the agent never packs to the full window
// (targets 35–50% for source, caps at 80%, reserves output headroom). Sub-32K
// models set VULTURE_LLM_CTX_SIZE. Go const and the Python default share this.
const DefaultContextWindow = 32_000

// contextWindows is the exact-match table (tokens), mirroring Python CONTEXT_WINDOWS.
var contextWindows = map[string]int{
	"gpt-4o":        128_000,
	"claude-sonnet": 200_000,
	"gemini-pro":    1_048_576,
	"qwen3:1.7b":    32_000,
	"qwen3:8b":      32_000,
	"qwen3:14b":     32_000,
	"llama3.2":      128_000,
	"mistral":       32_000,
	// §31.1: OpenAI o-series + newer/legacy exact ids (dated snapshots fall to
	// the family rules / default). o-series are exact-only to avoid a fragile
	// short "o1"/"o3" substring that could false-match another provider's id.
	"o1":            200_000,
	"o1-mini":       128_000,
	"o3":            200_000,
	"o3-mini":       200_000,
	"o4-mini":       200_000,
	"gpt-4.1":       1_047_576,
	"gpt-4.1-mini":  1_047_576,
	"gpt-4.1-nano":  1_047_576,
	"gpt-3.5-turbo": 16_385, // OVERSHOOT fix: was defaulting to 32000 > real 16385
}

// modelFamilyCtx maps a family substring → window, checked IN ORDER (first
// substring match on the lowercased id wins), mirroring Python _MODEL_FAMILY_CTX.
// §31 additions over the Python set: gemma-3 (before generic gemma), glm, gemini.
var modelFamilyCtx = []struct {
	sub string
	ctx int
}{
	// ORDER MUST MATCH Python _MODEL_FAMILY_CTX exactly (first-substring-match
	// wins): identical values AND identical positions, else a broker run
	// (Go-resolved) and a non-broker run (Python-resolved) can disagree on a
	// multi-family id. gemma-3 precedes generic gemma; generic gemma sits after
	// mixtral (matching Python), so a "gemma-<other-family>" id resolves the same
	// on both sides.
	{"gemma-3", 131_072},  // §31: gemma-3 is 128K — precedes generic gemma (8K)
	{"glm", 131_072},      // §31: GLM-4.5/4.6/5.x are 128K–200K
	{"gemini", 1_048_576}, // §31: gemini-1.5/2.x are 1M+
	{"qwen3", 32_768},
	{"qwen2.5", 32_768},
	{"qwen", 32_768},
	{"llama-3", 128_000},
	{"llama3", 128_000},
	{"llama", 128_000},
	{"mistral", 32_000},
	{"mixtral", 32_000},
	{"gemma", 8_192},
	{"phi-3", 128_000},
	{"phi-4", 16_384},
	{"deepseek", 64_000},
	{"codestral", 32_000},
	{"command-r", 128_000},
	{"claude", 200_000},
	{"gpt-4.1", 1_047_576}, // §31.1: gpt-4.1* is 1M — MUST precede generic gpt-4 (contains "gpt-4")
	{"gpt-3.5", 16_385},    // §31.1: legacy 16K — precedes gpt-4 for clarity (no substring overlap)
	{"gpt-4", 128_000},
}

// ContextWindow resolves a model to its context window (tokens): exact-map →
// ordered family-substring inference → DefaultContextWindow.
func ContextWindow(model string) int {
	if w, ok := contextWindows[model]; ok {
		return w
	}
	lm := strings.ToLower(model)
	for _, f := range modelFamilyCtx {
		if strings.Contains(lm, f.sub) {
			return f.ctx
		}
	}
	return DefaultContextWindow
}

// ResolveContextWindow honors an explicit override (VULTURE_LLM_CTX_SIZE) first
// — a positive integer wins over the registry — else falls back to
// ContextWindow(model). Mirrors the agent's env-first resolution priority.
func ResolveContextWindow(model, override string) int {
	if override != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(override)); err == nil && n > 0 {
			return n
		}
	}
	return ContextWindow(model)
}
