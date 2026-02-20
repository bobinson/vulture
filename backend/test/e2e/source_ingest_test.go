//go:build e2e

package e2e

import (
	"testing"
)

func TestSourceIngestLocalPath(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	srcDir := createTestSourceDir(t)

	resp, err := httpPost(addr, "/api/sources", map[string]string{
		"type": "local",
		"path": srcDir,
	})
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	readJSON(t, resp, &result)

	if result["id"] == nil || result["id"] == "" {
		t.Fatal("expected non-empty source id")
	}
	if result["path"] != srcDir {
		t.Fatalf("expected path=%q, got %q", srcDir, result["path"])
	}
	if result["type"] != "local" {
		t.Fatalf("expected type=local, got %q", result["type"])
	}
	fc, ok := result["file_count"].(float64)
	if !ok || fc < 1 {
		t.Fatalf("expected file_count >= 1, got %v", result["file_count"])
	}
}

func TestSourceIngestLocalPathNotFound(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, err := httpPost(addr, "/api/sources", map[string]string{
		"type": "local",
		"path": "/nonexistent/path/12345",
	})
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSourceIngestGitURL(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, err := httpPost(addr, "/api/sources", map[string]string{
		"type": "git",
		"url":  "https://github.com/octocat/Hello-World.git",
	})
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	readJSON(t, resp, &result)

	if result["id"] == nil || result["id"] == "" {
		t.Fatal("expected non-empty source id")
	}
	if result["type"] != "git" {
		t.Fatalf("expected type=git, got %q", result["type"])
	}
	path, _ := result["path"].(string)
	if path == "" {
		t.Fatal("expected non-empty cloned path")
	}
}

func TestSourceIngestMissingType(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, err := httpPost(addr, "/api/sources", map[string]string{
		"path": "/some/path",
	})
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}
