package main

import (
	"strings"
	"testing"
)

// TestLLMEndpointStartupError covers the 0065 §2.2/§H5 startup gate seam: strict
// vs degrade, the allow-insecure bypass, and the §R2 exclusion of internal
// agent/broker URLs. (Audit finding #3 — previously untested.)
func TestLLMEndpointStartupError(t *testing.T) {
	// Neutralize every input this function reads so ambient env can't leak in.
	reset := func(t *testing.T) {
		t.Setenv("VULTURE_ALLOW_INSECURE_LLM", "")
		t.Setenv("VULTURE_STRICT_LLM_ENDPOINT", "")
		t.Setenv("OPENAI_BASE_URL", "")
		t.Setenv("VULTURE_EMBEDDING_URL", "")
		t.Setenv("VULTURE_LLM_BROKER_URL", "")
	}

	t.Run("secure endpoints pass", func(t *testing.T) {
		reset(t)
		t.Setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
		if err := llmEndpointStartupError(); err != nil {
			t.Fatalf("https endpoint should pass, got %v", err)
		}
	})

	t.Run("insecure endpoint degrades by default (nil + warn)", func(t *testing.T) {
		reset(t)
		t.Setenv("OPENAI_BASE_URL", "http://llm-proxy.internal:8000/v1")
		if err := llmEndpointStartupError(); err != nil {
			t.Fatalf("default mode must degrade (nil), got %v", err)
		}
	})

	t.Run("strict mode hard-fails on insecure endpoint", func(t *testing.T) {
		reset(t)
		t.Setenv("OPENAI_BASE_URL", "http://llm-proxy.internal:8000/v1")
		t.Setenv("VULTURE_STRICT_LLM_ENDPOINT", "true")
		err := llmEndpointStartupError()
		if err == nil || !strings.Contains(err.Error(), "strict mode") {
			t.Fatalf("strict mode must return a boot error mentioning strict mode, got %v", err)
		}
	})

	t.Run("allow-insecure bypass returns nil even when strict+insecure", func(t *testing.T) {
		reset(t)
		t.Setenv("OPENAI_BASE_URL", "http://llm-proxy.internal:8000/v1")
		t.Setenv("VULTURE_STRICT_LLM_ENDPOINT", "true")
		t.Setenv("VULTURE_ALLOW_INSECURE_LLM", "true")
		if err := llmEndpointStartupError(); err != nil {
			t.Fatalf("allow-insecure must bypass the gate, got %v", err)
		}
	})

	t.Run("R2: internal broker URL is excluded from the check", func(t *testing.T) {
		reset(t)
		// Only the broker URL is insecure; the two checked endpoints are empty.
		t.Setenv("VULTURE_LLM_BROKER_URL", "http://broker.internal:9000")
		t.Setenv("VULTURE_STRICT_LLM_ENDPOINT", "true")
		if err := llmEndpointStartupError(); err != nil {
			t.Fatalf("internal broker URL must NOT be validated (R2), got %v", err)
		}
	})
}
