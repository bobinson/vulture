//go:build e2e

package e2e

import (
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, err := httpGet(addr, "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]string
	readJSON(t, resp, &result)

	if result["status"] != "healthy" {
		t.Fatalf("expected status=healthy, got %q", result["status"])
	}
}
