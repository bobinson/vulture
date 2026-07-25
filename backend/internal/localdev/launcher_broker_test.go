package localdev

import (
	"strings"
	"testing"
)

// getenvMap adapts a map to the getenv func signature used by agentBrokerEnv.
func getenvMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// Feature 0064 §25.2: with the broker OFF (Mode A default), no broker env is
// added and the provider key is NOT withheld — nothing changes.
func TestAgentBrokerEnv_Off_NoChange(t *testing.T) {
	entries, withhold := agentBrokerEnv(getenvMap(map[string]string{}))
	if withhold {
		t.Error("broker off must not withhold the provider key")
	}
	if len(entries) != 0 {
		t.Errorf("broker off must add no env entries, got %v", entries)
	}
}

// With the broker ON, the agent gets VULTURE_LLM_BROKER + VULTURE_LLM_BROKER_URL
// and the provider key MUST be withheld (N1: keys live only in the backend).
func TestAgentBrokerEnv_On_WithholdsKeyAndInjectsURL(t *testing.T) {
	entries, withhold := agentBrokerEnv(getenvMap(map[string]string{
		"VULTURE_LLM_BROKER":     "on",
		"VULTURE_LLM_BROKER_URL": "http://localhost:8090/v1",
	}))
	if !withhold {
		t.Fatal("broker on MUST withhold the provider key from the agent (N1 key isolation)")
	}
	joined := strings.Join(entries, "\n")
	if !strings.Contains(joined, "VULTURE_LLM_BROKER=on") {
		t.Errorf("missing VULTURE_LLM_BROKER=on in %v", entries)
	}
	if !strings.Contains(joined, "VULTURE_LLM_BROKER_URL=http://localhost:8090/v1") {
		t.Errorf("missing VULTURE_LLM_BROKER_URL in %v", entries)
	}
}

// A truthy VULTURE_LLM_BROKER without an explicit URL still withholds the key
// and flips the broker on (the agent falls back to its default broker URL).
func TestAgentBrokerEnv_On_NoURL_StillWithholds(t *testing.T) {
	entries, withhold := agentBrokerEnv(getenvMap(map[string]string{"VULTURE_LLM_BROKER": "true"}))
	if !withhold {
		t.Fatal("broker on MUST withhold the provider key even without an explicit URL")
	}
	if !strings.Contains(strings.Join(entries, "\n"), "VULTURE_LLM_BROKER=on") {
		t.Errorf("missing VULTURE_LLM_BROKER=on in %v", entries)
	}
}
