//go:build e2e

package e2e

import (
	"testing"

	"github.com/vulture/backend/internal/config"
)

func TestAgentListEndpoint(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, err := httpGet(addr, "/api/agents")
	if err != nil {
		t.Fatalf("GET /api/agents: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var agents []map[string]interface{}
	readJSON(t, resp, &agents)

	// No assertion on the COUNT. The registry grows as agents are added (it was 3
	// when this was written and is 10 now), and a literal count pins today's
	// roster rather than the property the test is for: that the endpoint returns
	// the configured agents. Membership is asserted below, which is what matters
	// and does not break every time an agent ships.
	if len(agents) == 0 {
		t.Fatalf("expected at least one agent, got none")
	}

	typeSet := map[string]bool{}
	for _, a := range agents {
		tp, _ := a["type"].(string)
		typeSet[tp] = true
	}

	for _, expected := range []string{"chaos", "owasp", "soc2"} {
		if !typeSet[expected] {
			t.Errorf("missing agent type %q", expected)
		}
	}
}

func TestAgentProxyDispatch(t *testing.T) {
	mockAddr, mockCleanup := startMockAgentServer(t)
	defer mockCleanup()

	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{
		Name: "Chaos Engineering",
		Type: "chaos",
		URL:  "http://" + mockAddr,
	}

	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	// Create source
	srcDir := createTestSourceDir(t)
	resp, err := httpPost(addr, "/api/sources", map[string]string{
		"type": "local",
		"path": srcDir,
	})
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}
	var srcResult map[string]interface{}
	readJSON(t, resp, &srcResult)
	sourceID := srcResult["id"].(string)

	// Create audit with mock agent configured
	resp, err = httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": sourceID,
		"types":     []string{"chaos"},
		"config":    map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var auditResult map[string]interface{}
	readJSON(t, resp, &auditResult)

	if auditResult["id"] == nil || auditResult["id"] == "" {
		t.Fatal("expected non-empty audit id")
	}
}
