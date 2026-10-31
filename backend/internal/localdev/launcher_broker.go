package localdev

import (
	"strings"

	"github.com/vulture/backend/internal/config"
)

// agentBrokerEnv returns the broker-related env entries a spawned agent needs
// (feature 0064 §25.2, Mode A), and whether the provider API key must be
// WITHHELD from the agent process. In broker mode the backend is the sole key
// holder (N1 key isolation): the agent gets a per-run token at dispatch, never
// a raw provider key.
//
// The broker is ON by default whenever an LLM is in use (VULTURE_USE_LLM), so
// the key is withheld by default on any LLM run; config.BrokerEnabled is the
// single decision both this spawn path and the backend's loadBrokerConfig use,
// so they cannot disagree. Skills-only (LLM off) ⇒ no entries, no withholding —
// the Mode A default, unchanged. An explicit VULTURE_LLM_BROKER=off opts out.
func agentBrokerEnv(getenv func(string) string) (entries []string, withholdKey bool) {
	if !config.BrokerEnabled(getenv) {
		return nil, false
	}
	entries = append(entries, "VULTURE_LLM_BROKER=on")
	url := strings.TrimSpace(getenv("VULTURE_LLM_BROKER_URL"))
	if url == "" {
		// Reachable without extra config: derive from the internal listen addr.
		url = config.DefaultBrokerURL(getenv("VULTURE_LLM_BROKER_LISTEN"))
	}
	if url != "" {
		entries = append(entries, "VULTURE_LLM_BROKER_URL="+url)
	}
	return entries, true
}
