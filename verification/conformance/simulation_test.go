package conformance

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"testing"
	"time"
)

type Manifest struct {
	TargetURL string        `json:"target_url"`
	Endpoints ManifestEP    `json:"endpoints"`
	Vulns     ManifestVulns `json:"vulnerabilities"`
}

type ManifestEP struct {
	Discovered  []string `json:"expected_discovered"`
	FromOpenAPI []string `json:"expected_from_openapi"`
}

type ManifestVulns struct {
	MustFind    []MustFind    `json:"must_find"`
	MustNotFind []MustNotFind `json:"must_not_find"`
}

type MustFind struct {
	ID      string `json:"id"`
	Pattern string `json:"title_pattern"`
	Sev     string `json:"severity_min"`
}

type MustNotFind struct {
	ID      string `json:"id"`
	Pattern string `json:"title_pattern"`
}

func loadManifest(t *testing.T) Manifest {
	t.Helper()
	data, err := os.ReadFile("../simulated-target/manifest.json")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return m
}

func waitForTarget(t *testing.T, url string) {
	t.Helper()
	for i := 0; i < 30; i++ {
		if resp, err := http.Get(url + "/health"); err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("target unreachable: %s", url)
}

func TestSim_ManifestPatternsCompile(t *testing.T) {
	m := loadManifest(t)
	for _, v := range m.Vulns.MustFind {
		if _, err := regexp.Compile(v.Pattern); err != nil {
			t.Errorf("%s: bad pattern %q: %v", v.ID, v.Pattern, err)
		}
	}
	for _, v := range m.Vulns.MustNotFind {
		if _, err := regexp.Compile(v.Pattern); err != nil {
			t.Errorf("%s: bad pattern %q: %v", v.ID, v.Pattern, err)
		}
	}
}

func TestSim_TargetEndpointsReachable(t *testing.T) {
	if testing.Short() {
		t.Skip("requires live target")
	}
	m := loadManifest(t)
	waitForTarget(t, m.TargetURL)
	for _, ep := range m.Endpoints.Discovered {
		resp, err := http.Get(m.TargetURL + ep)
		if err != nil {
			t.Errorf("%s unreachable: %v", ep, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Errorf("%s returned %d", ep, resp.StatusCode)
		}
	}
}

func TestSim_PlantedVulnsPresent(t *testing.T) {
	if testing.Short() {
		t.Skip("requires live target")
	}
	m := loadManifest(t)
	waitForTarget(t, m.TargetURL)

	// VULN_001: .env accessible
	resp, err := http.Get(m.TargetURL + "/.env")
	if err != nil || resp.StatusCode != 200 {
		t.Error("VULN_001: /.env should be accessible")
	} else {
		resp.Body.Close()
	}

	// VULN_002: no HSTS
	resp, err = http.Get(m.TargetURL + "/")
	if err != nil {
		t.Fatalf("target unreachable: %v", err)
	}
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Error("VULN_002: should NOT have HSTS")
	}

	// VULN_003: X-Powered-By
	if resp.Header.Get("X-Powered-By") == "" {
		t.Error("VULN_003: should have X-Powered-By")
	}
	resp.Body.Close()

	// FALSE_001: no directory listing
	resp, err = http.Get(m.TargetURL + "/nonexistent/dir/")
	if err == nil {
		if resp.StatusCode != 404 {
			t.Errorf("FALSE_001: expected 404, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestSim_OracleTraceTransitions(t *testing.T) {
	// This only tests oracle trace structure (doesn't need live target)
	stages := []string{"scan", "discover", "prove"}

	r1 := oracleAdvance(t, AdvanceInput{Status: "scan_running", Stages: stages, Index: 0}, "completed")
	if r1.Status != "discover_running" {
		t.Errorf("scan→ expected discover_running, got %s", r1.Status)
	}

	r2 := oracleAdvance(t, AdvanceInput{Status: "discover_running", Stages: stages, Index: 1}, "completed")
	if r2.Status != "prove_running" {
		t.Errorf("discover→ expected prove_running, got %s", r2.Status)
	}

	r3 := oracleAdvance(t, AdvanceInput{Status: "prove_running", Stages: stages, Index: 2}, "completed")
	if r3.Status != "completed" {
		t.Errorf("prove→ expected completed, got %s", r3.Status)
	}
}
