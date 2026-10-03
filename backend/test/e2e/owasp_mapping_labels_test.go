//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
)

// Feature 0096 P1: the backend applies an OWASP mapping result to the FINAL,
// deduplicated finding set. The OWASP agent returns its edition's CWE->category
// table and no findings; every CWE-categorised finding of every scan agent is
// labelled by `category`, the lineage row keeps the FULL table per
// framework:edition, and a mapping-mode run touches no lineage row of its own.
//
// Every agent here is a scripted mock that answers with a fixed result, so the
// tests drive the backend with exactly the wire shape of LLD §2.2 without the
// real agent (which does not speak mapping v1 until P3).

// mappingCat is one category entry of a mapping table.
type mappingCat struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

var (
	catA01 = mappingCat{"A01", "Broken Access Control"}
	catA04 = mappingCat{"A04", "Cryptographic Failures"}
	catA05 = mappingCat{"A05", "Injection"}
	catA07 = mappingCat{"A07", "Authentication Failures"}
)

// owaspMappingResult renders a mapping-mode OWASP result (LLD §2.2). extra is
// merged into the payload (e.g. an owasp_coverage manifest).
func owaspMappingResult(t *testing.T, edition string, selected []string, table map[string][]mappingCat, extra map[string]interface{}) string {
	t.Helper()
	if selected == nil {
		selected = []string{}
	}
	payload := map[string]interface{}{
		"findings": []interface{}{},
		"score":    83,
		"summary":  "owasp mapping",
		"mapping": map[string]interface{}{
			"version": 1, "framework": "owasp", "edition": edition,
			"selected": selected, "table": table,
		},
	}
	for k, v := range extra {
		payload[k] = v
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal mapping result: %v", err)
	}
	return string(b)
}

// scanFinding is one finding row of a scripted scan agent's result.
type scanFinding struct {
	Category, Title, File string
	Line                  int
}

// scanResult renders a scan agent's result with deterministic (skill) rows,
// so a row's absence on a later scan is a closure the backend may act on.
func scanResult(t *testing.T, rows ...scanFinding) string {
	t.Helper()
	findings := make([]map[string]interface{}, 0, len(rows))
	for _, r := range rows {
		findings = append(findings, map[string]interface{}{
			"severity": "high", "category": r.Category, "title": r.Title,
			"description": "d", "file_path": r.File, "line_start": r.Line, "line_end": r.Line,
			"recommendation": "r", "provenance": "skill",
			"check_id": "chk." + strings.ToLower(strings.ReplaceAll(r.Category, "-", "_")),
		})
	}
	b, err := json.Marshal(map[string]interface{}{"findings": findings, "summary": "scan", "score": 70})
	if err != nil {
		t.Fatalf("marshal scan result: %v", err)
	}
	return string(b)
}

// labelsAudit is the subset of GET /api/audits/{id} these tests read.
type labelsAudit struct {
	ID            string          `json:"id"`
	Status        string          `json:"status"`
	Findings      []model.Finding `json:"findings"`
	Scores        map[string]int  `json:"scores"`
	OwaspCoverage json.RawMessage `json:"owasp_coverage"`
}

// labelledLineageRow is a lineage row as the API returns it, labels included.
type labelledLineageRow struct {
	ID               string              `json:"id"`
	AgentType        string              `json:"agent_type"`
	Category         string              `json:"category"`
	CurrentStatus    string              `json:"current_status"`
	LatestAuditID    string              `json:"latest_audit_id"`
	ComplianceLabels map[string][]string `json:"compliance_labels"`
}

// labelsHarness is one backend with scripted agents and one local source.
type labelsHarness struct {
	addr, dir, sourceID string
	dbPath              string
}

func newLabelsHarness(t *testing.T, agents map[string]*scriptedAgent) *labelsHarness {
	t.Helper()
	cfg := testConfig(t)
	for at, a := range agents {
		cfg.Agents[at] = config.AgentConfig{Name: strings.ToUpper(at), Type: at, URL: a.srv.URL}
	}
	addr, cleanup := startTestServer(t, cfg)
	t.Cleanup(cleanup)
	dir := createTestSourceDir(t)
	resp, err := httpPost(addr, "/api/sources", map[string]string{"type": "local", "path": dir})
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}
	var src map[string]interface{}
	readJSON(t, resp, &src)
	sourceID, _ := src["id"].(string)
	if sourceID == "" {
		t.Fatalf("no source id in %v", src)
	}
	return &labelsHarness{addr: addr, dir: dir, sourceID: sourceID, dbPath: cfg.DBPath}
}

// run starts one audit, waits for it to complete, and returns it as persisted.
func (h *labelsHarness) run(t *testing.T, types []string, auditCfg map[string]interface{}) labelsAudit {
	t.Helper()
	body := map[string]interface{}{"source_id": h.sourceID, "types": types}
	if auditCfg != nil {
		body["config"] = auditCfg
	}
	resp, err := httpPost(h.addr, "/api/audits", body)
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	var created map[string]interface{}
	readJSON(t, resp, &created)
	auditID, _ := created["id"].(string)
	if auditID == "" {
		t.Fatalf("no audit id in %v", created)
	}
	if final := pollAuditStatus(t, h.addr, auditID, 15*time.Second); final["status"] != "completed" {
		t.Fatalf("audit %s ended %q (%v), want completed", auditID, final["status"], final["degraded_reason"])
	}
	resp, err = httpGet(h.addr, "/api/audits/"+auditID)
	if err != nil {
		t.Fatalf("GET audit: %v", err)
	}
	var a labelsAudit
	readJSON(t, resp, &a)
	return a
}

// lineage lists every active lineage row of the source, labels included.
func (h *labelsHarness) lineage(t *testing.T) []labelledLineageRow {
	t.Helper()
	resp, err := httpGet(h.addr, "/api/lineage?limit=500&source_path="+h.dir)
	if err != nil {
		t.Fatalf("GET /api/lineage: %v", err)
	}
	var rows []labelledLineageRow
	readJSON(t, resp, &rows)
	return rows
}

// waitLineage polls until cond holds over the source's lineage rows.
func (h *labelsHarness) waitLineage(t *testing.T, what string, cond func([]labelledLineageRow) bool) []labelledLineageRow {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var rows []labelledLineageRow
	for time.Now().Before(deadline) {
		if rows = h.lineage(t); cond(rows) {
			return rows
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s; rows=%+v", what, rows)
	return nil
}

func rowsOfAgent(rows []labelledLineageRow, agent string) []labelledLineageRow {
	var out []labelledLineageRow
	for _, r := range rows {
		if r.AgentType == agent {
			out = append(out, r)
		}
	}
	return out
}

func rowByCategory(rows []labelledLineageRow, agent, category string) (labelledLineageRow, bool) {
	for _, r := range rows {
		if r.AgentType == agent && r.Category == category {
			return r, true
		}
	}
	return labelledLineageRow{}, false
}

func findingByCategory(t *testing.T, a labelsAudit, category string) model.Finding {
	t.Helper()
	var hit []model.Finding
	for _, f := range a.Findings {
		if f.Category == category {
			hit = append(hit, f)
		}
	}
	if len(hit) != 1 {
		t.Fatalf("audit %s: %d findings with category %s, want exactly 1; findings=%+v", a.ID, len(hit), category, a.Findings)
	}
	return hit[0]
}

func owaspLabel(edition string, cat mappingCat, cwe string) model.ComplianceLabel {
	return model.ComplianceLabel{Framework: "owasp", Edition: edition,
		CategoryID: cat.ID, CategoryName: cat.Name, CWE: cwe}
}

func assertNoOwaspRows(t *testing.T, a labelsAudit) {
	t.Helper()
	for _, f := range a.Findings {
		if f.AgentType == "owasp" {
			t.Errorf("audit %s persisted an agent_type=owasp finding %q; a mapping-mode run persists ZERO (0096 I1)", a.ID, f.Title)
		}
	}
}

func assertNoLabels(t *testing.T, a labelsAudit, why string) {
	t.Helper()
	for _, f := range a.Findings {
		if f.ComplianceLabels != nil {
			t.Errorf("audit %s finding %q (%s/%s) carries labels %+v; %s",
				a.ID, f.Title, f.AgentType, f.Category, f.ComplianceLabels, why)
		}
	}
}

var (
	rowSecret = scanFinding{"CWE-798", "Hardcoded credential", "main.go", 1}
	rowSQLi   = scanFinding{"CWE-89", "SQL injection", "db.go", 10}
)

func TestMappingLabelsEveryCWECategorisedFinding(t *testing.T) {
	table := map[string][]mappingCat{
		"CWE-798": {catA07},
		"CWE-89":  {catA05},
		"CWE-79":  {catA05},
	}
	cwe := newScriptedAgent(t, scanResult(t, rowSecret, rowSQLi,
		scanFinding{"CWE-1234", "Weakness the edition does not map", "x.go", 2}))
	xss := newScriptedAgent(t, scanResult(t, scanFinding{"CWE-79", "Reflected XSS", "view.html", 5}))
	chaos := newScriptedAgent(t, scanResult(t, scanFinding{"retry", "No retry on outbound call", "svc.go", 3}))
	owasp := newScriptedAgent(t, owaspMappingResult(t, "2025", nil, table, nil))
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "xss": xss, "chaos": chaos, "owasp": owasp})

	a := h.run(t, []string{"cwe", "xss", "chaos", "owasp"}, nil)

	assertNoOwaspRows(t, a)
	if len(a.Findings) != 5 {
		t.Fatalf("persisted %d findings, want the 5 scan rows (no OWASP copies); findings=%+v", len(a.Findings), a.Findings)
	}
	for _, tc := range []struct {
		category string
		want     []model.ComplianceLabel
	}{
		{"CWE-798", []model.ComplianceLabel{owaspLabel("2025", catA07, "CWE-798")}},
		{"CWE-89", []model.ComplianceLabel{owaspLabel("2025", catA05, "CWE-89")}},
		// Another scan agent's CWE row is labelled exactly like the CWE agent's.
		{"CWE-79", []model.ComplianceLabel{owaspLabel("2025", catA05, "CWE-79")}},
		// A CWE the edition does not map gets NO label, not an empty one.
		{"CWE-1234", nil},
		// A finding without a CWE category is not the mapping's to label.
		{"retry", nil},
	} {
		f := findingByCategory(t, a, tc.category)
		if !reflect.DeepEqual(f.ComplianceLabels, tc.want) {
			t.Errorf("%s (%s): compliance_labels = %+v, want %+v", tc.category, f.AgentType, f.ComplianceLabels, tc.want)
		}
	}
	if a.Scores["owasp"] != 83 {
		t.Errorf("the mapping result's score must still be recorded: scores=%v", a.Scores)
	}
}

func TestMappingLabelsTheDedupSurvivor(t *testing.T) {
	// CWE-79 and CWE-80 are one taxonomy family, so the same site from two
	// agents collapses to ONE finding. The loser is not persisted, so its
	// categories ride on the survivor (0096 H2): one label per (category,
	// cwe), each naming the CWE that contributed it.
	table := map[string][]mappingCat{"CWE-79": {catA05}, "CWE-80": {catA05}}
	cwe := newScriptedAgent(t, scanResult(t, scanFinding{"CWE-79", "Cross-site scripting", "view.html", 5}))
	xss := newScriptedAgent(t, scanResult(t, scanFinding{"CWE-80", "Reflected XSS in template", "view.html", 5}))
	owasp := newScriptedAgent(t, owaspMappingResult(t, "2025", nil, table, nil))
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "xss": xss, "owasp": owasp})

	a := h.run(t, []string{"cwe", "xss", "owasp"}, nil)

	assertNoOwaspRows(t, a)
	if len(a.Findings) != 1 {
		t.Fatalf("persisted %d findings, want the ONE dedup survivor; findings=%+v", len(a.Findings), a.Findings)
	}
	survivor := a.Findings[0]
	// cross_agent_origins is not a stored column; the L3 validation check the
	// merge appends is, and it is the persisted evidence the two rows merged.
	if checks := fmt.Sprint(survivor.Validation["checks"]); !strings.Contains(checks, "cross_agent") {
		t.Fatalf("fixture did not dedup: survivor %+v carries no cross_agent check", survivor)
	}
	want := sortedLabels([]model.ComplianceLabel{owaspLabel("2025", catA05, "CWE-79"), owaspLabel("2025", catA05, "CWE-80")})
	if !reflect.DeepEqual(sortedLabels(survivor.ComplianceLabels), want) {
		t.Errorf("dedup survivor (%s %s) labels = %+v, want %+v",
			survivor.AgentType, survivor.Category, survivor.ComplianceLabels, want)
	}
}

func TestMappingSelectedCategoriesOnFindingsFullOnLineage(t *testing.T) {
	// The audit asked for A07 only. Findings carry the selected subset; the
	// lineage row carries the FULL table, so a later run that selects other
	// categories finds the row's labels already complete (LLD §4.2).
	table := map[string][]mappingCat{
		"CWE-798": {catA07},
		"CWE-89":  {catA05},
		"CWE-259": {catA07, catA04},
	}
	cwe := newScriptedAgent(t, scanResult(t, rowSecret, rowSQLi,
		scanFinding{"CWE-259", "Hard-coded password", "auth.go", 4}))
	owasp := newScriptedAgent(t, owaspMappingResult(t, "2025", []string{"A07"}, table, nil))
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "owasp": owasp})

	a := h.run(t, []string{"cwe", "owasp"}, map[string]interface{}{
		"owasp": map[string]interface{}{"categories": []string{"A07"}},
	})

	assertNoOwaspRows(t, a)
	for _, tc := range []struct {
		category string
		want     []model.ComplianceLabel
	}{
		{"CWE-798", []model.ComplianceLabel{owaspLabel("2025", catA07, "CWE-798")}},
		{"CWE-89", nil},
		{"CWE-259", []model.ComplianceLabel{owaspLabel("2025", catA07, "CWE-259")}},
	} {
		if f := findingByCategory(t, a, tc.category); !reflect.DeepEqual(f.ComplianceLabels, tc.want) {
			t.Errorf("finding %s: compliance_labels = %+v, want the selected subset %+v", tc.category, f.ComplianceLabels, tc.want)
		}
	}

	wantLineage := map[string][]string{
		"CWE-798": {"A07"},
		"CWE-89":  {"A05"},
		"CWE-259": {"A07", "A04"},
	}
	rows := h.waitLineage(t, "three labelled cwe rows", func(r []labelledLineageRow) bool {
		return len(rowsOfAgent(r, "cwe")) == 3
	})
	for category, cats := range wantLineage {
		row, ok := rowByCategory(rows, "cwe", category)
		if !ok {
			t.Fatalf("no cwe lineage row for %s; rows=%+v", category, rows)
		}
		if want := map[string][]string{"owasp:2025": cats}; !reflect.DeepEqual(row.ComplianceLabels, want) {
			t.Errorf("lineage %s: compliance_labels = %v, want the FULL table %v", category, row.ComplianceLabels, want)
		}
	}
	if n := len(rowsOfAgent(rows, "owasp")); n != 0 {
		t.Errorf("a mapping-mode run must create no owasp lineage row, got %d", n)
	}
}

func TestEmptyMappingTouchesNoLineage(t *testing.T) {
	// Scan 1 is a LEGACY OWASP agent: its copy row owns a lineage row. Scan 2
	// is mapping mode with an EMPTY table (R1): zero labels, and the existing
	// OWASP row is neither closed nor re-sighted nor given any event.
	cwe := newScriptedAgent(t, mappingCWEResult)
	owasp := newScriptedAgent(t, legacyOwaspCopy,
		owaspMappingResult(t, "2025", nil, map[string][]mappingCat{}, nil))
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "owasp": owasp})

	h.run(t, []string{"cwe", "owasp"}, nil)
	owaspRow := h.seedPre0096OwaspRow(t)
	_, before := lineageDetail(t, h.addr, owaspRow.ID)

	second := h.run(t, []string{"cwe", "owasp"}, nil)
	assertNoOwaspRows(t, second)
	assertNoLabels(t, second, "an empty mapping labels nothing")

	rows := h.waitLineage(t, "scan 2's cwe re-sighting", func(r []labelledLineageRow) bool {
		c := rowsOfAgent(r, "cwe")
		return len(c) == 1 && c[0].LatestAuditID == second.ID
	})
	// Grace window: the owasp pass shares the cwe pass's goroutine, in
	// either order, so give a wrongly-run closure time to land.
	time.Sleep(500 * time.Millisecond)
	status, after := lineageDetail(t, h.addr, owaspRow.ID)
	if status != "open" {
		t.Fatalf("an empty mapping closed OWASP lineage row %s: status %q, want open (0096 I3)", owaspRow.ID, status)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("an empty mapping must record ZERO lineage events on an OWASP row: before %v, after %v", before, after)
	}
	for _, r := range rowsOfAgent(h.lineage(t), "owasp") {
		if r.LatestAuditID == second.ID {
			t.Errorf("owasp row %s was re-sighted by the mapping-mode run", r.ID)
		}
	}
	if c := rowsOfAgent(rows, "cwe")[0]; c.ComplianceLabels != nil {
		t.Errorf("an empty table carries no edition knowledge; cwe row labels = %v, want none", c.ComplianceLabels)
	}
}

func TestMappingFromOtherAgentIgnored(t *testing.T) {
	// Only the backend-assigned owasp agent may answer with a mapping (R13).
	// A scan agent's result carrying one is an ordinary result: the mapping is
	// not applied, and — the half that matters for lineage — it does not opt
	// that agent out of its own closure pass either.
	mapping := `{"version":1,"framework":"owasp","edition":"2025","selected":[],` +
		`"table":{"CWE-798":[{"id":"A07","name":"Authentication Failures"}],` +
		`"CWE-79":[{"id":"A05","name":"Injection"}]}}`
	withMapping := func(result string) string {
		return strings.TrimSuffix(result, "}") + `,"mapping":` + mapping + `}`
	}
	cwe := newScriptedAgent(t, scanResult(t, rowSecret))
	xss := newScriptedAgent(t,
		withMapping(scanResult(t, scanFinding{"CWE-79", "Reflected XSS", "view.html", 5})),
		withMapping(scanResult(t)))
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "xss": xss})

	first := h.run(t, []string{"cwe", "xss"}, nil)
	assertNoLabels(t, first, "a mapping from a non-owasp agent must be ignored")
	rows := h.waitLineage(t, "the xss and cwe rows", func(r []labelledLineageRow) bool {
		return len(rowsOfAgent(r, "xss")) == 1 && len(rowsOfAgent(r, "cwe")) == 1
	})
	for _, r := range rows {
		if r.ComplianceLabels != nil {
			t.Errorf("lineage row %s (%s) carries labels %v from an ignored mapping", r.ID, r.AgentType, r.ComplianceLabels)
		}
	}

	// Scan 2: xss reports nothing (still carrying a mapping). Its row is a
	// deterministic one, so the xss closure pass must still run and close it.
	xssRow := rowsOfAgent(rows, "xss")[0]
	h.run(t, []string{"cwe", "xss"}, nil)
	deadline := time.Now().Add(10 * time.Second)
	status, _ := lineageDetail(t, h.addr, xssRow.ID)
	for ; status != "fixed" && time.Now().Before(deadline); status, _ = lineageDetail(t, h.addr, xssRow.ID) {
		time.Sleep(50 * time.Millisecond)
	}
	if status != "fixed" {
		t.Fatalf("a mapping on a SCAN agent's result must not exempt it from lineage: xss row %s is %q, want fixed",
			xssRow.ID, status)
	}
}

func TestInvalidMappingDropped(t *testing.T) {
	// All-or-nothing validation (LLD §3.4). An invalid mapping is dropped, the
	// run completes, nothing is labelled — and the result is still a
	// mapping-mode answer, so even an OWASP copy row it carries is not
	// persisted: an invalid mapping never falls back to legacy persistence.
	bigTable := make(map[string][]mappingCat, 2001)
	for i := 0; i < 2001; i++ {
		bigTable[fmt.Sprintf("CWE-%d", 10000+i)] = []mappingCat{catA05}
	}
	bigJSON, _ := json.Marshal(bigTable)
	okTable := `{"CWE-798":[{"id":"A07","name":"Authentication Failures"}]}`
	mapping := func(version, framework, edition, selected, table string) string {
		return fmt.Sprintf(`{"version":%s,"framework":%q,"edition":%q,"selected":%s,"table":%s}`,
			version, framework, edition, selected, table)
	}
	cases := []struct{ name, mapping string }{
		{"version 2", mapping("2", "owasp", "2025", `[]`, okTable)},
		{"framework not owasp", mapping("1", "asvs", "2025", `[]`, okTable)},
		{"edition not four digits", mapping("1", "owasp", "25", `[]`, okTable)},
		{"table key not a CWE id", mapping("1", "owasp", "2025", `[]`,
			`{"CWE-798":[{"id":"A07","name":"Authentication Failures"}],"CWE-ABC":[{"id":"A05","name":"Injection"}]}`)},
		{"category id malformed", mapping("1", "owasp", "2025", `[]`, `{"CWE-798":[{"id":"X07","name":"Auth"}]}`)},
		{"category name too long", mapping("1", "owasp", "2025", `[]`,
			`{"CWE-798":[{"id":"A07","name":"`+strings.Repeat("n", 121)+`"}]}`)},
		{"category name with NUL", mapping("1", "owasp", "2025", `[]`, `{"CWE-798":[{"id":"A07","name":"Auth\u0000"}]}`)},
		{"selected id malformed", mapping("1", "owasp", "2025", `["A7"]`, okTable)},
		{"table not an object", mapping("1", "owasp", "2025", `[]`, `[]`)},
		{"table over 2000 keys", mapping("1", "owasp", "2025", `[]`, string(bigJSON))},
	}
	results := make([]string, len(cases))
	for i, c := range cases {
		results[i] = `{"findings":[{"severity":"high","category":"A07","title":"A07 copy row",` +
			`"description":"d","file_path":"auth.go","line_start":4,"line_end":4,"recommendation":"r",` +
			`"provenance":"skill","check_id":"owasp.A07.cwe_798"}],"summary":"owasp","score":80,"mapping":` + c.mapping + `}`
	}
	cwe := newScriptedAgent(t, mappingCWEResult)
	owasp := newScriptedAgent(t, results...)
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "owasp": owasp})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := h.run(t, []string{"cwe", "owasp"}, nil)
			assertNoLabels(t, a, "an invalid mapping must be dropped whole")
			assertNoOwaspRows(t, a)
			if len(a.Findings) != 1 {
				t.Errorf("persisted %d findings, want the 1 cwe row; findings=%+v", len(a.Findings), a.Findings)
			}
		})
	}
}

// coverageCategory is one category of the persisted owasp_coverage manifest.
type coverageCategory struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	MappedCount int      `json:"mapped_count"`
	FoundCWEs   []string `json:"found_cwes"`
	FoundCount  int      `json:"found_count"`
	Status      string   `json:"status"`
	SourceURL   string   `json:"source_url"`
}

func TestCoverageFoundCountMatchesPersistedLabels(t *testing.T) {
	// The agent's manifest is computed from PRE-dedup priors (R10). Here it
	// claims CWE-798 under A07 although no persisted row has it, and says A01
	// is clean although CWE-22 is persisted. The backend recomputes from the
	// final, labelled set; mapped_count, names and provenance are the agent's.
	// CWE-79 and CWE-80 dedup into one finding, which carries both CWEs'
	// labels (0096 H2), so A05 counts all three of CWE-79, CWE-80, CWE-89.
	table := map[string][]mappingCat{
		"CWE-79": {catA05}, "CWE-80": {catA05}, "CWE-89": {catA05},
		"CWE-798": {catA07}, "CWE-22": {catA01},
	}
	agentManifest := map[string]interface{}{
		"edition":          "2025",
		"cwe_stage_status": "completed",
		"categories": []map[string]interface{}{
			{"id": "A01", "name": "Broken Access Control", "mapped_count": 40, "found_cwes": []string{},
				"found_count": 0, "status": "clean-or-undetected", "source_url": "https://owasp.example/A01"},
			{"id": "A05", "name": "Injection", "mapped_count": 37, "found_cwes": []string{"CWE-79", "CWE-80", "CWE-89"},
				"found_count": 3, "status": "found", "source_url": "https://owasp.example/A05"},
			{"id": "A07", "name": "Authentication Failures", "mapped_count": 36, "found_cwes": []string{"CWE-798"},
				"found_count": 1, "status": "found", "source_url": "https://owasp.example/A07"},
		},
		"unmapped_cwes":  []string{},
		"unmapped_count": 0,
	}
	cwe := newScriptedAgent(t, scanResult(t,
		scanFinding{"CWE-79", "Cross-site scripting", "view.html", 5},
		rowSQLi,
		scanFinding{"CWE-22", "Path traversal", "files.go", 7}))
	xss := newScriptedAgent(t, scanResult(t, scanFinding{"CWE-80", "Reflected XSS in template", "view.html", 5}))
	owasp := newScriptedAgent(t, owaspMappingResult(t, "2025", nil, table,
		map[string]interface{}{"owasp_coverage": agentManifest}))
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "xss": xss, "owasp": owasp})

	a := h.run(t, []string{"cwe", "xss", "owasp"}, nil)

	labelled := map[string]map[string]bool{}
	for _, f := range a.Findings {
		for _, l := range f.ComplianceLabels {
			if labelled[l.CategoryID] == nil {
				labelled[l.CategoryID] = map[string]bool{}
			}
			labelled[l.CategoryID][l.CWE] = true
		}
	}
	var manifest struct {
		Edition        string             `json:"edition"`
		CWEStageStatus string             `json:"cwe_stage_status"`
		Categories     []coverageCategory `json:"categories"`
	}
	if err := json.Unmarshal(a.OwaspCoverage, &manifest); err != nil {
		t.Fatalf("persisted owasp_coverage %s: %v", a.OwaspCoverage, err)
	}
	if manifest.Edition != "2025" || manifest.CWEStageStatus != "completed" || len(manifest.Categories) != 3 {
		t.Fatalf("manifest provenance must be the agent's: %+v", manifest)
	}
	wantCounts := map[string]int{"A01": 1, "A05": 3, "A07": 0}
	for _, c := range manifest.Categories {
		var want []string
		for cweID := range labelled[c.ID] {
			want = append(want, cweID)
		}
		sort.Strings(want)
		got := append([]string(nil), c.FoundCWEs...)
		sort.Strings(got)
		if c.FoundCount != len(want) || c.FoundCount != wantCounts[c.ID] || !reflect.DeepEqual(nonNil(got), nonNil(want)) {
			t.Errorf("%s: found_count=%d found_cwes=%v, want %d distinct labelled CWE(s) %v",
				c.ID, c.FoundCount, c.FoundCWEs, wantCounts[c.ID], want)
		}
		wantStatus := "clean-or-undetected"
		if c.FoundCount > 0 {
			wantStatus = "found"
		}
		if c.Status != wantStatus {
			t.Errorf("%s: status %q, want %q for found_count %d", c.ID, c.Status, wantStatus, c.FoundCount)
		}
		if c.MappedCount == 0 || c.Name == "" || c.SourceURL == "" {
			t.Errorf("%s: the agent's mapped_count/name/source_url must survive: %+v", c.ID, c)
		}
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func TestLineageLabelsSurviveNonMappingScans(t *testing.T) {
	// R9: lineage labels are keyed per framework:edition and replaced only by
	// a run of THAT edition. A CWE-only rescan is a sighting with no mapping
	// and must leave them alone; a 2021 run adds its key beside 2025's.
	cwe := newScriptedAgent(t, scanResult(t, rowSecret))
	owasp := newScriptedAgent(t,
		owaspMappingResult(t, "2025", nil, map[string][]mappingCat{"CWE-798": {catA07}}, nil),
		owaspMappingResult(t, "2021", nil, map[string][]mappingCat{"CWE-798": {catA04}}, nil))
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "owasp": owasp})

	labelsOfCWERow := func(auditID string) map[string][]string {
		rows := h.waitLineage(t, "the cwe row sighted by "+auditID, func(r []labelledLineageRow) bool {
			c := rowsOfAgent(r, "cwe")
			return len(c) == 1 && c[0].LatestAuditID == auditID
		})
		return rowsOfAgent(rows, "cwe")[0].ComplianceLabels
	}

	first := h.run(t, []string{"cwe", "owasp"}, nil)
	if got, want := labelsOfCWERow(first.ID), map[string][]string{"owasp:2025": {"A07"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after the 2025 mapping run: lineage labels %v, want %v", got, want)
	}

	cweOnly := h.run(t, []string{"cwe"}, nil)
	assertNoLabels(t, cweOnly, "a CWE-only scan has no mapping to apply")
	if got, want := labelsOfCWERow(cweOnly.ID), map[string][]string{"owasp:2025": {"A07"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("a CWE-only rescan must keep the lineage labels: got %v, want %v", got, want)
	}

	third := h.run(t, []string{"cwe", "owasp"}, map[string]interface{}{"owasp": map[string]interface{}{"edition": "2021"}})
	if f := findingByCategory(t, third, "CWE-798"); !reflect.DeepEqual(f.ComplianceLabels,
		[]model.ComplianceLabel{owaspLabel("2021", catA04, "CWE-798")}) {
		t.Errorf("2021 run: finding labels %+v, want the 2021 edition's", f.ComplianceLabels)
	}
	want := map[string][]string{"owasp:2025": {"A07"}, "owasp:2021": {"A04"}}
	if got := labelsOfCWERow(third.ID); !reflect.DeepEqual(got, want) {
		t.Fatalf("a 2021 run must add its key and never overwrite 2025's: got %v, want %v", got, want)
	}
}

func TestLegacyOwaspAgentUnderNewBackend(t *testing.T) {
	// R2 / §2.3: a pre-0096 OWASP agent ignores accepts_mapping and answers
	// with copy rows. The backend persists them exactly as before — the
	// copies are findings, nothing is labelled, the agent's manifest is kept
	// verbatim — but (0096 M1) a mapper agent never owns lineage in ANY mode:
	// no copy creates a lineage row, and no legacy run re-sights or closes the
	// OWASP row a pre-0096 backend left behind, whatever copies it carries.
	manifest := `{"edition":"2025","cwe_stage_status":"completed","categories":[{"id":"A07",` +
		`"name":"Authentication Failures","mapped_count":36,"found_cwes":["CWE-798"],"found_count":1,` +
		`"status":"found","source_url":"u"}],"unmapped_cwes":[],"unmapped_count":0}`
	sqliCopy := `{"severity":"high","category":"A05","title":"A05 Injection: SQL injection","description":"d",` +
		`"file_path":"query.go","line_start":9,"line_end":9,"recommendation":"r","provenance":"skill",` +
		`"check_id":"owasp.A05.cwe_89"}`
	twoCopies := strings.Replace(legacyOwaspCopy, `"}],"summary"`, `"},`+sqliCopy+`],"summary"`, 1)
	twoCopiesWithManifest := strings.TrimSuffix(twoCopies, "}") + `,"owasp_coverage":` + manifest + `}`
	cwe := newScriptedAgent(t, mappingCWEResult)
	owasp := newScriptedAgent(t, twoCopiesWithManifest, legacyOwaspOtherCopy, legacyOwaspEmpty)
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "owasp": owasp})

	first := h.run(t, []string{"cwe", "owasp"}, nil)
	assertNoLabels(t, first, "legacy mode applies no mapping")
	copies := 0
	for _, f := range first.Findings {
		if f.AgentType == "owasp" {
			copies++
		}
	}
	if copies != 2 {
		t.Fatalf("legacy OWASP copies must still be persisted: got %d owasp rows, want 2; findings=%+v", copies, first.Findings)
	}
	var gotManifest, wantManifest interface{}
	_ = json.Unmarshal(first.OwaspCoverage, &gotManifest)
	_ = json.Unmarshal([]byte(manifest), &wantManifest)
	if !reflect.DeepEqual(gotManifest, wantManifest) {
		t.Errorf("legacy mode must persist the agent's manifest verbatim:\n got %s\nwant %s", first.OwaspCoverage, manifest)
	}
	h.waitLineage(t, "scan 1's cwe row", func(r []labelledLineageRow) bool { return len(rowsOfAgent(r, "cwe")) == 1 })
	h.assertOnlySeededOwaspLineage(t, "", first.ID)

	// A row a pre-0096 backend left behind. Scan 2 carries a DIFFERENT copy
	// (under 0063 a closure of this row); scan 3 carries none.
	seeded := h.seedPre0096OwaspRow(t)
	_, before := lineageDetail(t, h.addr, seeded.ID)
	for _, scan := range []string{"another copy", "no copy"} {
		a := h.run(t, []string{"cwe", "owasp"}, nil)
		if scan == "another copy" && len(a.Findings) != 2 {
			t.Fatalf("scan with %s: want the cwe row and the copy persisted, got %+v", scan, a.Findings)
		}
		h.waitLineage(t, "the cwe re-sighting", func(r []labelledLineageRow) bool {
			c := rowsOfAgent(r, "cwe")
			return len(c) == 1 && c[0].LatestAuditID == a.ID
		})
		time.Sleep(500 * time.Millisecond)
		status, after := lineageDetail(t, h.addr, seeded.ID)
		if status != "open" || !reflect.DeepEqual(before, after) {
			t.Fatalf("legacy scan with %s touched the pre-0096 owasp row %s: status %q, events before %v, after %v "+
				"(0096 M1: mapper agents do not own lineage)", scan, seeded.ID, status, before, after)
		}
		h.assertOnlySeededOwaspLineage(t, seeded.ID, a.ID)
	}
}

// seedPre0096OwaspRow clones the source's one cwe lineage row as the OWASP row
// a pre-0096 backend would have left (see seedOwaspLineageRow) and returns it.
func (h *labelsHarness) seedPre0096OwaspRow(t *testing.T) labelledLineageRow {
	t.Helper()
	cweRows := rowsOfAgent(h.waitLineage(t, "the cwe row to clone", func(r []labelledLineageRow) bool {
		return len(rowsOfAgent(r, "cwe")) == 1
	}), "cwe")
	id := seedOwaspLineageRow(t, h.dbPath, cweRows[0].ID)
	rows := h.waitLineage(t, "the seeded owasp row", func(r []labelledLineageRow) bool {
		o := rowsOfAgent(r, "owasp")
		return len(o) == 1 && o[0].ID == id
	})
	return rowsOfAgent(rows, "owasp")[0]
}

// assertOnlySeededOwaspLineage fails if any owasp lineage row other than the
// seeded one (none when seededID is "") exists — a copy that created a row.
func (h *labelsHarness) assertOnlySeededOwaspLineage(t *testing.T, seededID, auditID string) {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	for _, r := range rowsOfAgent(h.lineage(t), "owasp") {
		if r.ID != seededID {
			t.Errorf("audit %s: owasp lineage row %s (%s) exists; a 0096 backend never writes lineage for a mapper agent (M1)",
				auditID, r.ID, r.Category)
		}
	}
}
