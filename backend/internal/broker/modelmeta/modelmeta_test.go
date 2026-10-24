package modelmeta

import "testing"

func TestContextWindow_ExactMap(t *testing.T) {
	if got := ContextWindow("gpt-4o"); got != 128_000 {
		t.Errorf("gpt-4o = %d, want 128000", got)
	}
	if got := ContextWindow("claude-sonnet"); got != 200_000 {
		t.Errorf("claude-sonnet = %d, want 200000", got)
	}
}

func TestContextWindow_FamilyInference(t *testing.T) {
	cases := map[string]int{
		"z-ai/glm-5.2":            131_072, // §31: GLM family (the bug that motivated this)
		"gemini-2.5-flash":        1_048_576,
		"gemma-3-27b-it":          131_072, // gemma-3 wins over generic gemma
		"gemma-2-9b":              8_192,
		"qwen/qwen3.6-35b-a3b":    32_768,
		"meta-llama/llama-3.1-8b": 128_000,
		"mistral-large":           32_000,
		"deepseek-r1":             64_000,
	}
	for model, want := range cases {
		if got := ContextWindow(model); got != want {
			t.Errorf("ContextWindow(%q) = %d, want %d", model, got, want)
		}
	}
}

func TestContextWindow_ClaudeAndOpenAI(t *testing.T) {
	cases := map[string]int{
		// Claude — the `claude` family covers every id (snapshots, prefixed, 3/4).
		"claude-3-5-sonnet-20241022":  200_000,
		"claude-sonnet-4-5":           200_000,
		"anthropic/claude-3.7-sonnet": 200_000,
		"claude-3-5-haiku-latest":     200_000,
		// OpenAI — §31.1 coverage for o-series + gpt-4.1 (1M) + the gpt-3.5 overshoot fix.
		"gpt-4o":        128_000,
		"gpt-4o-mini":   128_000,
		"gpt-4-turbo":   128_000,
		"gpt-4.1":       1_047_576,
		"gpt-4.1-mini":  1_047_576,
		"o1":            200_000,
		"o1-mini":       128_000,
		"o3-mini":       200_000,
		"o4-mini":       200_000,
		"gpt-3.5-turbo": 16_385,
	}
	for model, want := range cases {
		if got := ContextWindow(model); got != want {
			t.Errorf("ContextWindow(%q) = %d, want %d", model, got, want)
		}
	}
}

func TestContextWindow_UnknownDefault(t *testing.T) {
	if got := ContextWindow("totally-unknown-model-xyz"); got != DefaultContextWindow {
		t.Errorf("unknown = %d, want DefaultContextWindow %d", got, DefaultContextWindow)
	}
	if DefaultContextWindow != 32_000 {
		t.Errorf("DefaultContextWindow = %d, want 32000", DefaultContextWindow)
	}
}

// TestFamilyOrder_MirrorsPython is a canary: the family substrings are matched
// first-match-wins, so their ORDER and VALUES must stay identical to the Python
// _MODEL_FAMILY_CTX, and the exact-match map must equal Python CONTEXT_WINDOWS
// (agents/shared/shared/llm/provider.py), else a broker run (Go-resolved) and a
// non-broker run (Python-resolved) size the same model differently (§31 review
// finding). 0074 AC6 / T1.7 (extension signed off, T0.7): the tables are read
// from the Python source itself rather than a hand-copied list, so ANY drift —
// a key, a value, a position — fails here. Before 0074 the canary compared
// family order only and missed that Python's exact map carries "gemini-flash"
// with no Go twin.
func TestFamilyOrder_MirrorsPython(t *testing.T) {
	py := readPythonProvider(t)
	assertFamilyParity(t, parsePyFamilies(t, py))
	assertExactParity(t, parsePyExact(t, py))
}

func TestResolveContextWindow_OverrideWins(t *testing.T) {
	if got := ResolveContextWindow("z-ai/glm-5.2", "50000"); got != 50_000 {
		t.Errorf("explicit override = %d, want 50000", got)
	}
	// blank / invalid / non-positive override → fall back to the registry.
	if got := ResolveContextWindow("z-ai/glm-5.2", ""); got != 131_072 {
		t.Errorf("no override = %d, want registry 131072", got)
	}
	if got := ResolveContextWindow("z-ai/glm-5.2", "not-a-number"); got != 131_072 {
		t.Errorf("bad override = %d, want registry 131072", got)
	}
	if got := ResolveContextWindow("gpt-4o", "0"); got != 128_000 {
		t.Errorf("zero override = %d, want registry 128000", got)
	}
}
