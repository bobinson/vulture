package localdev

import "github.com/vulture/backend/internal/config"

// agentBrokerEnv returns the broker-related env entries a spawned agent needs
// (feature 0064 §25.2, Mode A), and whether the provider API key must be
// WITHHELD from the agent process. In broker mode the backend is the sole key
// holder (N1 key isolation): the agent gets a per-run token at dispatch, never
// a raw provider key. Broker OFF ⇒ no entries and no withholding — the Mode A
// default is unchanged.
func agentBrokerEnv(getenv func(string) string) (entries []string, withholdKey bool) {
	if !config.ParseFlag(getenv("VULTURE_LLM_BROKER"), false) {
		return nil, false
	}
	entries = append(entries, "VULTURE_LLM_BROKER=on")
	if u := getenv("VULTURE_LLM_BROKER_URL"); u != "" {
		entries = append(entries, "VULTURE_LLM_BROKER_URL="+u)
	}
	return entries, true
}
