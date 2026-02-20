//go:build e2e

package e2e

import (
	"testing"
)

func TestStatsEndpoint(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, err := httpGet(addr, "/api/stats")
	if err != nil {
		t.Fatalf("GET /api/stats: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var stats map[string]interface{}
	readJSON(t, resp, &stats)

	// Stats should have standard fields even with no audits
	requiredFields := []string{"audits_run", "total_findings", "critical_issues", "average_score"}
	for _, field := range requiredFields {
		if _, ok := stats[field]; !ok {
			t.Errorf("missing stats field %q", field)
		}
	}
}

func TestStatsAfterCreatingAudit(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	// Create a source and audit
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
	resp.Body.Close()

	// Now check stats - should show at least 1 audit run
	resp, err = httpGet(addr, "/api/stats")
	if err != nil {
		t.Fatalf("GET /api/stats: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var stats map[string]interface{}
	readJSON(t, resp, &stats)

	auditsRun, _ := stats["audits_run"].(float64)
	if auditsRun < 1 {
		t.Fatalf("expected audits_run >= 1, got %v", stats["audits_run"])
	}
}
