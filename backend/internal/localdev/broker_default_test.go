package localdev

import (
	"strings"
	"testing"
)

func TestAgentBrokerEnv_OnWhenLLMUsedByDefault(t *testing.T) {
	get := func(k string) string {
		if k == "VULTURE_USE_LLM" {
			return "true"
		}
		return "" // broker + url unset
	}
	entries, withhold := agentBrokerEnv(get)
	joined := strings.Join(entries, "\n")
	if !withhold {
		t.Fatal("key must be withheld from the agent when the broker is on (LLM in use)")
	}
	if !strings.Contains(joined, "VULTURE_LLM_BROKER=on") {
		t.Fatalf("agent env should turn the broker on; got %q", joined)
	}
	if !strings.Contains(joined, "VULTURE_LLM_BROKER_URL=http://127.0.0.1:8090/v1") {
		t.Fatalf("broker URL should be derived from the default listen addr; got %q", joined)
	}
}

func TestAgentBrokerEnv_ExplicitOffWins(t *testing.T) {
	get := func(k string) string {
		switch k {
		case "VULTURE_USE_LLM":
			return "true"
		case "VULTURE_LLM_BROKER":
			return "off"
		}
		return ""
	}
	entries, withhold := agentBrokerEnv(get)
	if withhold || len(entries) != 0 {
		t.Fatal("VULTURE_LLM_BROKER=off must opt out even when LLM is in use")
	}
}

func TestAgentBrokerEnv_SkillsOnlyOff(t *testing.T) {
	entries, withhold := agentBrokerEnv(func(string) string { return "" })
	if withhold || len(entries) != 0 {
		t.Fatal("skills-only (no LLM) must not enable the broker")
	}
}
