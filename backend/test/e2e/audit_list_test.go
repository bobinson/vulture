//go:build e2e

package e2e

import (
	"testing"
)

func TestAuditListEmpty(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, err := httpGet(addr, "/api/audits")
	if err != nil {
		t.Fatalf("GET /api/audits: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var audits []interface{}
	readJSON(t, resp, &audits)

	if len(audits) != 0 {
		t.Fatalf("expected 0 audits, got %d", len(audits))
	}
}

func TestAuditListAfterCreate(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	// Create source + audit
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
		"types":     []string{"chaos", "owasp"},
		"config":    map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// List should contain the audit
	resp, err = httpGet(addr, "/api/audits?limit=10&offset=0")
	if err != nil {
		t.Fatalf("GET /api/audits: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var audits []map[string]interface{}
	readJSON(t, resp, &audits)

	if len(audits) < 1 {
		t.Fatal("expected at least 1 audit in list")
	}

	audit := audits[0]
	if audit["source_id"] != sourceID {
		t.Fatalf("expected source_id=%q, got %q", sourceID, audit["source_id"])
	}
}

func TestAuditListPagination(t *testing.T) {
	cfg := testConfig(t)
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

	// Create 3 audits
	for i := 0; i < 3; i++ {
		resp, err = httpPost(addr, "/api/audits", map[string]interface{}{
			"source_id": sourceID,
			"types":     []string{"chaos"},
			"config":    map[string]interface{}{},
		})
		if err != nil {
			t.Fatalf("POST /api/audits #%d: %v", i, err)
		}
		resp.Body.Close()
	}

	// Request with limit=2
	resp, err = httpGet(addr, "/api/audits?limit=2&offset=0")
	if err != nil {
		t.Fatalf("GET /api/audits: %v", err)
	}
	var page1 []map[string]interface{}
	readJSON(t, resp, &page1)

	if len(page1) != 2 {
		t.Fatalf("expected 2 audits on page 1, got %d", len(page1))
	}

	// Request offset=2
	resp, err = httpGet(addr, "/api/audits?limit=2&offset=2")
	if err != nil {
		t.Fatalf("GET /api/audits: %v", err)
	}
	var page2 []map[string]interface{}
	readJSON(t, resp, &page2)

	if len(page2) != 1 {
		t.Fatalf("expected 1 audit on page 2, got %d", len(page2))
	}
}
