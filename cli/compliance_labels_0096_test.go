package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Feature 0096: OWASP is no longer a second copy of every CWE-categorised
// finding. The backend labels each persisted finding with the OWASP Top 10
// categories its CWE maps to (`compliance_labels`), and the OWASP agent itself
// persists nothing. These tests pin what the CLI shows for such an audit:
//
//   - `--output json` carries each finding's `compliance_labels` verbatim;
//   - the human summary prints per-category counts under an
//     "OWASP Top 10:<edition>" heading when labels exist, and nothing when none;
//   - `--exit-on` counts one row per weakness — a label is never a row.

// mappingModeAudit is GET /api/audits/{id} for a 0096 audit of {cwe, xss,
// owasp}: three weaknesses, zero OWASP rows, labels on the CWE rows. The last
// finding carries two labels so a reader that expanded labels into rows would
// count four, not three.
const mappingModeAudit = `{
  "id": "aud-0096",
  "status": "completed",
  "types": ["cwe", "xss", "owasp"],
  "findings_count": 3,
  "findings": [
    {"id": "f1", "agent_type": "cwe", "severity": "high", "category": "CWE-89",
     "title": "SQL injection", "file_path": "app/db.py", "line_start": 12,
     "compliance_labels": [
       {"framework": "owasp", "edition": "2025", "category_id": "A05", "category_name": "Injection", "cwe": "CWE-89"}
     ]},
    {"id": "f2", "agent_type": "xss", "severity": "medium", "category": "CWE-79",
     "title": "Reflected XSS", "file_path": "web/view.tsx", "line_start": 40,
     "compliance_labels": [
       {"framework": "owasp", "edition": "2025", "category_id": "A05", "category_name": "Injection", "cwe": "CWE-79"}
     ]},
    {"id": "f3", "agent_type": "cwe", "severity": "critical", "category": "CWE-798",
     "title": "Hard-coded credential", "file_path": "config/settings.py", "line_start": 3,
     "compliance_labels": [
       {"framework": "owasp", "edition": "2025", "category_id": "A07", "category_name": "Authentication Failures", "cwe": "CWE-798"},
       {"framework": "owasp", "edition": "2025", "category_id": "A04", "category_name": "Cryptographic Failures", "cwe": "CWE-798"}
     ]}
  ]
}`

// cweOnlyAudit has no OWASP mapping at all: no labels, so no OWASP heading.
const cweOnlyAudit = `{
  "id": "aud-cwe",
  "status": "completed",
  "types": ["cwe"],
  "findings": [
    {"id": "f1", "agent_type": "cwe", "severity": "high", "category": "CWE-89",
     "title": "SQL injection", "file_path": "app/db.py", "line_start": 12}
  ]
}`

// legacyOwaspAudit is a pre-0096 audit: the OWASP agent re-emitted copies with
// `agent_type = owasp`. It carries no labels, so it renders exactly as before.
const legacyOwaspAudit = `{
  "id": "aud-legacy",
  "status": "completed",
  "types": ["cwe", "owasp"],
  "findings": [
    {"id": "f1", "agent_type": "cwe", "severity": "high", "category": "CWE-89",
     "title": "SQL injection", "file_path": "app/db.py", "line_start": 12},
    {"id": "f2", "agent_type": "owasp", "severity": "high", "category": "A05",
     "title": "[A05] SQL injection", "file_path": "app/db.py", "line_start": 12}
  ]
}`

// serveAudit stands up the audit endpoint the CLI reads and returns the audit
// exactly as the CLI decodes it on the wire (apiGet), so a field the CLI's
// types drop is dropped here too.
func serveAudit(t *testing.T, payload string) audit {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/audits/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, payload)
	}))
	defer srv.Close()
	return apiGet[audit](srv.URL+"/api/audits/x", "")
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	os.Stderr = orig
	return <-done
}

// summaryEnv pins the summary's link resolution so these tests do not depend
// on the developer's config.
func summaryEnv(t *testing.T) {
	t.Setenv("VULTURE_FRONTEND_URL", "http://ui.test")
	t.Setenv("VULTURE_CONFIG", "")
	t.Setenv("VULTURE_HOME", t.TempDir())
}

func TestE2E_0096_JSONOutputCarriesComplianceLabels(t *testing.T) {
	a := serveAudit(t, mappingModeAudit)
	out := captureStdout(t, func() { outputResult(a, ciFlags{output: "json"}, "http://api.test") })

	var got struct {
		Findings []struct {
			ID               string `json:"id"`
			ComplianceLabels []struct {
				Framework    string `json:"framework"`
				Edition      string `json:"edition"`
				CategoryID   string `json:"category_id"`
				CategoryName string `json:"category_name"`
				CWE          string `json:"cwe"`
			} `json:"compliance_labels"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json output does not parse: %v\n%s", err, out)
	}
	if len(got.Findings) != 3 {
		t.Fatalf("json output has %d findings, want 3 (one per weakness)", len(got.Findings))
	}
	want := map[string][]string{"f1": {"A05"}, "f2": {"A05"}, "f3": {"A07", "A04"}}
	for _, f := range got.Findings {
		if len(f.ComplianceLabels) != len(want[f.ID]) {
			t.Fatalf("finding %s: %d compliance_labels, want %d:\n%s", f.ID, len(f.ComplianceLabels), len(want[f.ID]), out)
		}
		for i, l := range f.ComplianceLabels {
			if l.Framework != "owasp" || l.Edition != "2025" || l.CategoryID != want[f.ID][i] || l.CategoryName == "" || l.CWE == "" {
				t.Errorf("finding %s label %d not carried verbatim: %+v", f.ID, i, l)
			}
		}
	}
}

// A finding with no labels must not grow an empty `compliance_labels` key:
// consumers of pre-0096 JSON see exactly the shape they saw before.
func TestE2E_0096_JSONOutputOmitsLabelsWhenNone(t *testing.T) {
	a := serveAudit(t, cweOnlyAudit)
	out := captureStdout(t, func() { outputResult(a, ciFlags{output: "json"}, "http://api.test") })
	if strings.Contains(out, "compliance_labels") {
		t.Fatalf("unlabelled finding must not carry a compliance_labels key:\n%s", out)
	}
}

func TestE2E_0096_SummaryPrintsOWASPCategoryCounts(t *testing.T) {
	summaryEnv(t)
	a := serveAudit(t, mappingModeAudit)
	out := captureStdout(t, func() { printAuditSummary(a, "http://api.test") })

	lines := trimmedLines(out)
	head := indexOf(lines, "OWASP Top 10:2025")
	if head < 0 {
		t.Fatalf("summary has no 'OWASP Top 10:2025' heading:\n%s", out)
	}
	// Categories in id order, each counting the findings labelled with it.
	want := []string{
		"A04 Cryptographic Failures: 1",
		"A05 Injection: 2",
		"A07 Authentication Failures: 1",
	}
	for i, w := range want {
		if head+1+i >= len(lines) || lines[head+1+i] != w {
			t.Fatalf("line %d under the heading: want %q\n%s", i+1, w, out)
		}
	}
	// Labels are not rows: the finding total stays one per weakness.
	if indexOf(lines, "Findings: 3") < 0 {
		t.Fatalf("summary must count 3 findings, not one per label:\n%s", out)
	}
}

func TestE2E_0096_SummaryPrintsNoOWASPHeadingWithoutLabels(t *testing.T) {
	summaryEnv(t)
	for name, payload := range map[string]string{"cwe-only": cweOnlyAudit, "pre-0096 copies": legacyOwaspAudit} {
		out := captureStdout(t, func() { printAuditSummary(serveAudit(t, payload), "http://api.test") })
		if strings.Contains(out, "OWASP Top 10") {
			t.Errorf("%s: no labels, so no OWASP heading expected:\n%s", name, out)
		}
	}
}

// Each edition present gets its own heading; categories never merge across
// editions, since A05 in 2021 and A05 in 2025 are different categories.
func TestE2E_0096_SummaryGroupsByEdition(t *testing.T) {
	summaryEnv(t)
	a := audit{ID: "two-editions", Status: "completed", Findings: []finding{
		{Severity: "high", Category: "CWE-89", ComplianceLabels: []complianceLabel{
			{Framework: "owasp", Edition: "2025", CategoryID: "A05", CategoryName: "Injection", CWE: "CWE-89"},
			{Framework: "owasp", Edition: "2021", CategoryID: "A03", CategoryName: "Injection", CWE: "CWE-89"},
		}},
	}}
	lines := trimmedLines(captureStdout(t, func() { printAuditSummary(a, "http://api.test") }))
	h21, h25 := indexOf(lines, "OWASP Top 10:2021"), indexOf(lines, "OWASP Top 10:2025")
	if h21 < 0 || h25 < 0 || h21 > h25 {
		t.Fatalf("want both edition headings, 2021 first: %q", lines)
	}
	if lines[h21+1] != "A03 Injection: 1" || lines[h25+1] != "A05 Injection: 1" {
		t.Fatalf("per-edition counts wrong: %q", lines)
	}
}

// --exit-on counts one row per weakness. A mapping-mode payload with N CWE
// findings and their labels yields N, never 2N: the OWASP view is a label on
// the row, not a second row that would double every threshold hit.
func TestE2E_0096_ExitOnCountsOneRowPerWeakness(t *testing.T) {
	a := serveAudit(t, mappingModeAudit)

	if got := countAtOrAbove(a, "low"); got != 3 {
		t.Fatalf("--exit-on low counted %d, want 3 (one per weakness, labels are not rows)", got)
	}
	if got := countAtOrAbove(a, "high"); got != 2 {
		t.Fatalf("--exit-on high counted %d, want 2", got)
	}

	var code int
	errOut := captureStderr(t, func() { code = computeExitCode(a, "high") })
	if code != 1 {
		t.Fatalf("findings at/above high must exit 1, got %d", code)
	}
	if !strings.Contains(errOut, "2 finding(s) at or above high") {
		t.Fatalf("exit 1 must say how many findings tripped the threshold, got stderr:\n%s", errOut)
	}
}

// Below the threshold the build passes and nothing is reported as tripping it.
func TestE2E_0096_ExitOnBelowThresholdIsSilent(t *testing.T) {
	a := serveAudit(t, cweOnlyAudit)
	var code int
	errOut := captureStderr(t, func() { code = computeExitCode(a, "critical") })
	if code != 0 || strings.Contains(errOut, "at or above") {
		t.Fatalf("below threshold: want exit 0 and no report, got %d / %q", code, errOut)
	}
}

func trimmedLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		lines = append(lines, strings.TrimSpace(l))
	}
	return lines
}

func indexOf(lines []string, want string) int {
	for i, l := range lines {
		if l == want {
			return i
		}
	}
	return -1
}
