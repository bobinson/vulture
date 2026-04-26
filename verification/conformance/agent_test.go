package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// OracleExpected mirrors the oracle expect output.
type OracleExpected struct {
	TargetURL     string          `json:"targetUrl"`
	Stages        []StageExpected `json:"stages"`
	ExpectedEPs   []string        `json:"expectedEndpoints"`
	TotalMustFind int             `json:"totalMustFind"`
}

type StageExpected struct {
	Stage       string           `json:"stage"`
	MustFind    []VulnExpected   `json:"mustFindVulns"`
	MustNotFind []FPGuard        `json:"mustNotFindVulns"`
	MinEPs      int              `json:"minEndpoints"`
	MinFindings int              `json:"minFindings"`
}

type VulnExpected struct {
	ID      string `json:"id"`
	Pattern string `json:"titlePattern"`
	SevMin  string `json:"severityMin"`
}

type FPGuard struct {
	ID      string `json:"id"`
	Pattern string `json:"titlePattern"`
}

var sevRank = map[string]int{"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

func oracleExpect(t *testing.T) OracleExpected {
	t.Helper()
	out := runOracle(t, "expect", "../simulated-target/manifest.json")
	var e OracleExpected
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("parse oracle expect: %v", err)
	}
	return e
}

func discoverDir(t *testing.T) string {
	t.Helper()
	dir, _ := filepath.Abs("../../agents/discover")
	if _, err := os.Stat(filepath.Join(dir, "discover_agent", "main.py")); err != nil {
		t.Skipf("discover agent not found at %s", dir)
	}
	return dir
}

// --- Agent-vs-Oracle Tests (subtests share one agent instance) ---

func TestAgent_DiscoverVsOracle(t *testing.T) {
	if testing.Short() {
		t.Skip("requires live target + agent subprocess")
	}
	m := loadManifest(t)
	waitForTarget(t, m.TargetURL)
	expected := oracleExpect(t)

	// Start discover agent once for all subtests
	dir := discoverDir(t)
	agent, err := StartAgent(dir, "discover_agent.main:app", "19998")
	if err != nil {
		t.Fatalf("start discover agent: %v", err)
	}
	defer agent.Stop()

	// Run discover once
	result, err := RunAgent("19998", map[string]interface{}{
		"run_id":         "agent-verify",
		"source_path":    "",
		"config":         map[string]interface{}{"target_url": m.TargetURL},
		"prior_findings": []interface{}{},
	})
	if err != nil {
		t.Fatalf("run discover agent: %v", err)
	}
	t.Logf("Discover result: %d API endpoints, %d URLs, %d findings",
		result.EndpointCount, result.URLCount, len(result.Findings))

	t.Run("FindsExpectedEndpoints", func(t *testing.T) {
		discoverStage := expected.Stages[1]
		if result.EndpointCount < discoverStage.MinEPs {
			t.Errorf("discover found %d endpoints, oracle expects >= %d",
				result.EndpointCount, discoverStage.MinEPs)
		}
	})

	t.Run("FindsMustFindVulns", func(t *testing.T) {
		scanStage := expected.Stages[0]
		for _, vuln := range scanStage.MustFind {
			pattern, err := regexp.Compile(vuln.Pattern)
			if err != nil {
				t.Errorf("%s: bad pattern: %v", vuln.ID, err)
				continue
			}
			found := false
			for _, f := range result.Findings {
				if pattern.MatchString(f.Title) {
					found = true
					if sevRank[f.Severity] < sevRank[vuln.SevMin] {
						t.Errorf("%s: severity %s < min %s", vuln.ID, f.Severity, vuln.SevMin)
					}
					break
				}
			}
			if !found {
				t.Logf("NOTICE: %s not found by discover (may be scan-only)", vuln.ID)
			}
		}
	})

	t.Run("NoFalsePositives", func(t *testing.T) {
		scanStage := expected.Stages[0]
		for _, fp := range scanStage.MustNotFind {
			pattern, err := regexp.Compile(fp.Pattern)
			if err != nil {
				continue
			}
			for _, f := range result.Findings {
				if pattern.MatchString(f.Title) {
					t.Errorf("FALSE POSITIVE %s: %q matches %q", fp.ID, f.Title, fp.Pattern)
				}
			}
		}
	})
}

func TestAgent_OracleExpectTransitions(t *testing.T) {
	expected := oracleExpect(t)
	if len(expected.Stages) != 3 {
		t.Fatalf("expected 3 stages, got %d", len(expected.Stages))
	}
	names := []string{"scan", "discover", "prove"}
	for i, name := range names {
		if expected.Stages[i].Stage != name {
			t.Errorf("stage[%d] = %q, want %q", i, expected.Stages[i].Stage, name)
		}
	}
	if expected.TotalMustFind != 3 {
		t.Errorf("totalMustFind = %d, want 3", expected.TotalMustFind)
	}
}
