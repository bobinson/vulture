//go:build e2e

package e2e

import (
	"testing"
)

func TestAuditCreateAndGet(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	// First create a source
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

	// Create audit
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

	auditID, ok := auditResult["id"].(string)
	if !ok || auditID == "" {
		t.Fatal("expected non-empty audit id")
	}
	if auditResult["status"] != "pending" && auditResult["status"] != "running" {
		t.Fatalf("expected status pending or running, got %q", auditResult["status"])
	}

	// Get audit
	resp, err = httpGet(addr, "/api/audits/"+auditID)
	if err != nil {
		t.Fatalf("GET /api/audits/%s: %v", auditID, err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var getResult map[string]interface{}
	readJSON(t, resp, &getResult)

	if getResult["id"] != auditID {
		t.Fatalf("expected id=%q, got %q", auditID, getResult["id"])
	}
	if getResult["source_id"] != sourceID {
		t.Fatalf("expected source_id=%q, got %q", sourceID, getResult["source_id"])
	}
}

func TestAuditCreateMissingSource(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, err := httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": "nonexistent-id",
		"types":     []string{"chaos"},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAuditGetNotFound(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, err := httpGet(addr, "/api/audits/nonexistent-id")
	if err != nil {
		t.Fatalf("GET /api/audits/nonexistent-id: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}
