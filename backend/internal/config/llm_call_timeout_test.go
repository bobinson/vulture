package config

import (
	"os"
	"testing"
)

// The broker's per-call budget is the FOURTH place this number lives, after
// the agent's batch bound, its socket read and its LiteLLM kwarg. It defaulted
// to a hardcoded 120 while the other three derived 439 — and because the Go
// broker sits between the agent and the provider, its 120 cut FIRST and
// returned 502 provider_unavailable, so the agent's correct 439s budget never
// got the chance to matter.
//
// Measured on a live LM Studio run (audit cde171bd): broker egress deadline at
// exactly T+120s, agent then burning its full 439s on retries, LLM tier
// contributing 0 of 34 findings.
func TestBrokerCallTimeoutDefaultsToTheDerivedBudget(t *testing.T) {
	t.Setenv("VULTURE_LLM_CALL_TIMEOUT_SEC", "")
	os.Unsetenv("VULTURE_LLM_CALL_TIMEOUT_SEC")

	cfg := Load()
	if cfg.Broker.CallTimeoutSec != DefaultLLMCallTimeoutSec {
		t.Fatalf("broker call timeout = %d, want %d (the derived per-call budget); "+
			"a shorter value here pre-empts the agent's own budget and surfaces as "+
			"502 provider_unavailable rather than as a timeout",
			cfg.Broker.CallTimeoutSec, DefaultLLMCallTimeoutSec)
	}
	if DefaultLLMCallTimeoutSec <= 120 {
		t.Fatalf("non-vacuity: the derived default must exceed the historical 120, "+
			"or this test cannot detect the hardcode it was written for (got %d)",
			DefaultLLMCallTimeoutSec)
	}
}

// An operator who sets the variable still wins outright, on every site.
func TestBrokerCallTimeoutHonoursAnExplicitSetting(t *testing.T) {
	t.Setenv("VULTURE_LLM_CALL_TIMEOUT_SEC", "900")
	if got := Load().Broker.CallTimeoutSec; got != 900 {
		t.Fatalf("broker call timeout = %d, want 900", got)
	}
}
