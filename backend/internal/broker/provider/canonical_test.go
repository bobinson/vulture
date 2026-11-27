package provider

import "testing"

// §30: the broker must have a concrete canonical endpoint for a native cloud
// provider so egress can SSRF-validate + pin it before the adapter runs.
func TestCanonicalBaseURL(t *testing.T) {
	cases := map[string]string{
		"openai":    "https://api.openai.com/v1",
		"gemini":    "https://generativelanguage.googleapis.com/v1beta",
		"anthropic": "https://api.anthropic.com",
		// no canonical endpoint — caller must supply a base URL.
		"openai-compatible": "",
		"ollama":            "",
		"unknown":           "",
	}
	for prov, want := range cases {
		if got := CanonicalBaseURL(prov); got != want {
			t.Errorf("CanonicalBaseURL(%q) = %q, want %q", prov, got, want)
		}
	}
}

// Only the native adapters leave the OpenAI wire protocol; every other name is
// served by an OpenAI-compatible adapter, so OPENAI_BASE_URL may feed it.
func TestSpeaksOpenAIWire(t *testing.T) {
	cases := map[string]bool{
		"":                  true,
		"openai":            true,
		"openai-compatible": true,
		"my-local-server":   true,
		"gemini":            false,
		"anthropic":         false,
	}
	for prov, want := range cases {
		if got := SpeaksOpenAIWire(prov); got != want {
			t.Errorf("SpeaksOpenAIWire(%q) = %v, want %v", prov, got, want)
		}
	}
}
