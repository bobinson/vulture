package egress

import "testing"

// RED phase — feature 0064 §7 (VULTURE_LLM_PROVIDER_ALLOWLIST).
//
// The operator allowlist gates which providers may be egressed to. Contract:
//   - A provider present in the configured set is Allowed.
//   - A provider absent from the set is NOT allowed.
//   - Matching is exact and case-sensitive (provider ids are canonical
//     lowercase tokens: openai, anthropic, gemini, ollama, openai-compat).
//   - An empty allowlist denies everything (fail-closed): with the broker
//     off / no allowlist configured, nothing egresses.
//
// The allowlist under test is constructed by NewAllowlist(providers...).
// Against the RED-phase scaffold these fail (NewAllowlist denies all).

func TestAllowlist_AllowsConfiguredProviders(t *testing.T) {
	al := NewAllowlist("openai", "anthropic")
	for _, p := range []string{"openai", "anthropic"} {
		if !al.Allowed(p) {
			t.Errorf("Allowed(%q) = false; want true (configured)", p)
		}
	}
}

func TestAllowlist_DeniesUnconfiguredProviders(t *testing.T) {
	al := NewAllowlist("openai")
	for _, p := range []string{"anthropic", "gemini", "evilcorp", ""} {
		if al.Allowed(p) {
			t.Errorf("Allowed(%q) = true; want false (not configured)", p)
		}
	}
}

func TestAllowlist_CaseSensitiveExactMatch(t *testing.T) {
	al := NewAllowlist("openai")
	for _, p := range []string{"OpenAI", "OPENAI", "openai "} {
		if al.Allowed(p) {
			t.Errorf("Allowed(%q) = true; want false (must be exact, case-sensitive)", p)
		}
	}
}

func TestAllowlist_EmptyDeniesAllFailClosed(t *testing.T) {
	al := NewAllowlist()
	for _, p := range []string{"openai", "anthropic", ""} {
		if al.Allowed(p) {
			t.Errorf("empty allowlist Allowed(%q) = true; want false (fail-closed)", p)
		}
	}
}
