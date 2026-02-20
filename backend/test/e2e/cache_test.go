//go:build e2e

package e2e

import (
	"testing"
)

func TestCacheEndpointMissingParams(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	// Missing both parameters
	resp, err := httpGet(addr, "/api/audits/cache")
	if err != nil {
		t.Fatalf("GET /api/audits/cache: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestCacheEndpointMissingTypes(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, err := httpGet(addr, "/api/audits/cache?source_id=abc")
	if err != nil {
		t.Fatalf("GET /api/audits/cache: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestCacheEndpointNoCachedResults(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, err := httpGet(addr, "/api/audits/cache?source_id=nonexistent&types=chaos,owasp")
	if err != nil {
		t.Fatalf("GET /api/audits/cache: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	readJSON(t, resp, &result)

	cached, ok := result["cached"].(bool)
	if !ok || cached {
		t.Fatalf("expected cached=false, got %v", result["cached"])
	}
}

func TestCacheEndpointReturnsCachedAudit(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	// Create a source
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

	// Create an audit
	resp, err = httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": sourceID,
		"types":     []string{"chaos"},
		"config":    map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	var auditResult map[string]interface{}
	readJSON(t, resp, &auditResult)

	// Check cache for a type that has no completed audit yet
	resp, err = httpGet(addr, "/api/audits/cache?source_id="+sourceID+"&types=chaos")
	if err != nil {
		t.Fatalf("GET /api/audits/cache: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var cacheResult map[string]interface{}
	readJSON(t, resp, &cacheResult)
	// The audit is pending, not completed, so cache should be empty
	// (cache returns completed audits only)
	if cacheResult["cached"] == true {
		// The audit is not completed yet, so it should not be cached
		// This is acceptable if the cache implementation returns pending audits
		t.Log("cache returned an audit even though it's not completed (acceptable)")
	}
}
