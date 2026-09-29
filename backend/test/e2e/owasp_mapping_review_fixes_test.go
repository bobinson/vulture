//go:build e2e

package e2e

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vulture/backend/internal/model"
)

// Feature 0096 review fixes, end to end. Every agent is a scripted mock, so
// each test drives the backend with exactly the wire shape it pins:
//
//   - H2  a dedup survivor keeps the OWASP categories of the CWE rows it
//         absorbed, each label naming the CWE that contributed it;
//   - M2  mapping mode is sticky for the run once any owasp snapshot used it;
//   - M3  only the owasp agent's result may carry the coverage manifest;
//   - M4  a manifest the backend cannot recount against the mapping is cleared,
//         and unmapped_cwes is recounted from the final set;
//   - M12 a zero-padded CWE id ("CWE-089") is that CWE, canonically.

// sevRow is one scan finding with an explicit severity, which is what decides
// the cross-agent dedup winner between two rows of one taxonomy family.
type sevRow struct {
	Severity, Category, Title, File string
	Line                            int
}

func sevResult(t *testing.T, extra map[string]interface{}, rows ...sevRow) string {
	t.Helper()
	findings := make([]map[string]interface{}, 0, len(rows))
	for _, r := range rows {
		findings = append(findings, map[string]interface{}{
			"severity": r.Severity, "category": r.Category, "title": r.Title,
			"description": "d", "file_path": r.File, "line_start": r.Line, "line_end": r.Line,
			"recommendation": "r", "provenance": "skill",
			"check_id": "chk." + strings.ToLower(strings.ReplaceAll(r.Category, "-", "_")),
		})
	}
	payload := map[string]interface{}{"findings": findings, "summary": "scan", "score": 70}
	for k, v := range extra {
		payload[k] = v
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal scan result: %v", err)
	}
	return string(b)
}

// coverageOf decodes the persisted manifest, with the unmapped half.
type recountedCoverage struct {
	Edition       string             `json:"edition"`
	Categories    []coverageCategory `json:"categories"`
	UnmappedCWEs  []string           `json:"unmapped_cwes"`
	UnmappedCount int                `json:"unmapped_count"`
}

func coverageOf(t *testing.T, a labelsAudit) recountedCoverage {
	t.Helper()
	var c recountedCoverage
	if err := json.Unmarshal(a.OwaspCoverage, &c); err != nil {
		t.Fatalf("audit %s owasp_coverage %s: %v", a.ID, a.OwaspCoverage, err)
	}
	return c
}

func coverageCat(t *testing.T, c recountedCoverage, id string) coverageCategory {
	t.Helper()
	for _, cat := range c.Categories {
		if cat.ID == id {
			return cat
		}
	}
	t.Fatalf("manifest has no category %s: %+v", id, c)
	return coverageCategory{}
}

// agentManifestFor renders a manifest the way the agent does, for the given
// categories, with deliberately WRONG pre-dedup counts the backend must redo.
func agentManifestFor(edition string, cats ...mappingCat) map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(cats))
	for _, c := range cats {
		out = append(out, map[string]interface{}{"id": c.ID, "name": c.Name, "mapped_count": 30,
			"found_cwes": []string{"CWE-9999"}, "found_count": 1, "status": "found",
			"source_url": "https://owasp.example/" + c.ID})
	}
	return map[string]interface{}{"edition": edition, "cwe_stage_status": "completed",
		"categories": out, "unmapped_cwes": []string{"CWE-4242"}, "unmapped_count": 1}
}

// labelsOf returns the labels of the one finding with this category, in a
// stable order, so a set of labels compares regardless of emission order.
func labelsOf(t *testing.T, a labelsAudit, category string) []model.ComplianceLabel {
	t.Helper()
	return sortedLabels(findingByCategory(t, a, category).ComplianceLabels)
}

func sortedLabels(labels []model.ComplianceLabel) []model.ComplianceLabel {
	out := append([]model.ComplianceLabel(nil), labels...)
	sort.Slice(out, func(i, j int) bool { return out[i].CategoryID+out[i].CWE < out[j].CategoryID+out[j].CWE })
	return out
}

var catA06 = mappingCat{"A06", "Insecure Design"}

func TestDedupSurvivorKeepsAbsorbedCategoryLabels(t *testing.T) {
	t.Run("CWE-943 survivor over a CWE-89 row", func(t *testing.T) {
		// {CWE-89, CWE-943} is one canonical family, so the same site from two
		// agents is ONE finding. The critical xss row wins; the edition maps
		// CWE-89 only. Labelled from its own category alone, the survivor
		// would lose A05 — the category the absorbed row was persisted for.
		table := map[string][]mappingCat{"CWE-89": {catA05}}
		cwe := newScriptedAgent(t, sevResult(t, nil, sevRow{"high", "CWE-89", "SQL injection", "db.go", 10}))
		xss := newScriptedAgent(t, sevResult(t, nil, sevRow{"critical", "CWE-943", "NoSQL injection", "db.go", 10}))
		owasp := newScriptedAgent(t, owaspMappingResult(t, "2025", nil, table,
			map[string]interface{}{"owasp_coverage": agentManifestFor("2025", catA05)}))
		h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "xss": xss, "owasp": owasp})

		a := h.run(t, []string{"cwe", "xss", "owasp"}, nil)

		assertNoOwaspRows(t, a)
		if len(a.Findings) != 1 || a.Findings[0].Category != "CWE-943" || a.Findings[0].AgentType != "xss" {
			t.Fatalf("fixture must dedup to the xss CWE-943 row; findings=%+v", a.Findings)
		}
		want := []model.ComplianceLabel{owaspLabel("2025", catA05, "CWE-89")}
		if got := labelsOf(t, a, "CWE-943"); !reflect.DeepEqual(got, want) {
			t.Errorf("survivor labels = %+v, want %+v: the absorbed CWE-89 row's category must survive the merge", got, want)
		}
		cov := coverageOf(t, a)
		if c := coverageCat(t, cov, "A05"); !reflect.DeepEqual(c.FoundCWEs, []string{"CWE-89"}) || c.FoundCount != 1 || c.Status != "found" {
			t.Errorf("A05 = %+v, want found_cwes [CWE-89] found_count 1 status found", c)
		}
		if !reflect.DeepEqual(cov.UnmappedCWEs, []string{"CWE-943"}) || cov.UnmappedCount != 1 {
			t.Errorf("unmapped = %v (%d), want [CWE-943] 1, recounted from the final set", cov.UnmappedCWEs, cov.UnmappedCount)
		}
		// The survivor's lineage row must carry the absorbed category too (LLD §4.2):
		// labelled from CWE-943 alone it would record "this edition maps nothing".
		assertSurvivorLineageLabels(t, h, "CWE-943", []string{"A05"})
	})

	t.Run("CWE-22/CWE-73 merge keeps both categories", func(t *testing.T) {
		// 2025 maps CWE-22 to A01 and CWE-73 to A06: one merged finding, two
		// categories, each naming its own CWE.
		table := map[string][]mappingCat{"CWE-22": {catA01}, "CWE-73": {catA06}}
		cwe := newScriptedAgent(t, sevResult(t, nil, sevRow{"high", "CWE-22", "Path traversal", "files.go", 7}))
		xss := newScriptedAgent(t, sevResult(t, nil, sevRow{"critical", "CWE-73", "External control of file name", "files.go", 7}))
		owasp := newScriptedAgent(t, owaspMappingResult(t, "2025", nil, table,
			map[string]interface{}{"owasp_coverage": agentManifestFor("2025", catA01, catA06)}))
		h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "xss": xss, "owasp": owasp})

		a := h.run(t, []string{"cwe", "xss", "owasp"}, nil)

		if len(a.Findings) != 1 {
			t.Fatalf("fixture must dedup to one finding; findings=%+v", a.Findings)
		}
		want := sortedLabels([]model.ComplianceLabel{
			owaspLabel("2025", catA01, "CWE-22"), owaspLabel("2025", catA06, "CWE-73"),
		})
		if got := labelsOf(t, a, a.Findings[0].Category); !reflect.DeepEqual(got, want) {
			t.Errorf("survivor labels = %+v, want %+v", got, want)
		}
		cov := coverageOf(t, a)
		if c := coverageCat(t, cov, "A01"); !reflect.DeepEqual(c.FoundCWEs, []string{"CWE-22"}) {
			t.Errorf("A01 found_cwes = %v, want [CWE-22]", c.FoundCWEs)
		}
		if c := coverageCat(t, cov, "A06"); !reflect.DeepEqual(c.FoundCWEs, []string{"CWE-73"}) {
			t.Errorf("A06 found_cwes = %v, want [CWE-73]", c.FoundCWEs)
		}
		if len(cov.UnmappedCWEs) != 0 || cov.UnmappedCount != 0 {
			t.Errorf("unmapped = %v (%d), want none", cov.UnmappedCWEs, cov.UnmappedCount)
		}
		assertSurvivorLineageLabels(t, h, a.Findings[0].Category, []string{"A01", "A06"})
	})
}

// assertSurvivorLineageLabels waits for the dedup survivor's lineage row and
// checks its owasp:2025 entry holds exactly the categories in want (order is
// the table's and the merge's, so the comparison is order-insensitive).
func assertSurvivorLineageLabels(t *testing.T, h *labelsHarness, category string, want []string) {
	t.Helper()
	rows := h.waitLineage(t, "survivor lineage row with labels", func(rs []labelledLineageRow) bool {
		for _, r := range rs {
			if r.Category == category && r.ComplianceLabels != nil {
				return true
			}
		}
		return false
	})
	for _, r := range rows {
		if r.Category != category {
			continue
		}
		got := append([]string(nil), r.ComplianceLabels["owasp:2025"]...)
		sort.Strings(got)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("survivor lineage owasp:2025 = %v, want %v: absorbed categories must reach lineage", got, want)
		}
		return
	}
	t.Fatalf("no lineage row for category %s", category)
}

// twoResultAgent answers every /run with TWO result frames in one stream.
func twoResultAgent(t *testing.T, first, second string) *scriptedAgent {
	t.Helper()
	a := &scriptedAgent{results: []string{first}}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/run") {
			w.WriteHeader(200)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		f, _ := w.(http.Flusher)
		for _, frame := range []string{
			"event: agent_start\ndata: {\"run_id\":\"r\"}\n\n",
			"event: result\ndata: " + first + "\n\n",
			"event: result\ndata: " + second + "\n\n",
			"event: agent_end\ndata: {}\n\n",
		} {
			_, _ = fmt.Fprint(w, frame)
			if f != nil {
				f.Flush()
			}
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func TestMappingModeIsStickyForTheRun(t *testing.T) {
	// The owasp agent answers in mapping mode, then sends a LEGACY snapshot
	// with a copy row. The run's mode was decided by the mapping answer: the
	// later snapshot must neither persist its copy nor drop the labels.
	mapping := owaspMappingResult(t, "2025", nil, map[string][]mappingCat{"CWE-798": {catA07}}, nil)
	owasp := twoResultAgent(t, mapping, legacyOwaspCopy)
	cwe := newScriptedAgent(t, mappingCWEResult)
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "owasp": owasp})

	a := h.run(t, []string{"cwe", "owasp"}, nil)

	assertNoOwaspRows(t, a)
	want := []model.ComplianceLabel{owaspLabel("2025", catA07, "CWE-798")}
	if got := labelsOf(t, a, "CWE-798"); !reflect.DeepEqual(got, want) {
		t.Errorf("cwe row labels = %+v, want %+v: a later legacy snapshot must not undo mapping mode", got, want)
	}
}

func TestScanAgentCoverageManifestIgnored(t *testing.T) {
	// Only the owasp agent's result is trusted for the coverage manifest,
	// exactly as for the mapping (R13). A scan agent's snapshot carrying one
	// must not become the audit's OWASP coverage — with or without an owasp
	// agent in the run.
	forged := map[string]interface{}{"owasp_coverage": agentManifestFor("2025", catA07)}
	cwe := newScriptedAgent(t, sevResult(t, forged, sevRow{"high", "CWE-798", "Hardcoded credential", "main.go", 1}))
	owasp := newScriptedAgent(t, owaspMappingResult(t, "2025", nil, map[string][]mappingCat{"CWE-798": {catA07}}, nil))
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "owasp": owasp})

	for _, types := range [][]string{{"cwe"}, {"cwe", "owasp"}} {
		a := h.run(t, types, nil)
		if len(a.OwaspCoverage) != 0 && string(a.OwaspCoverage) != "null" {
			t.Errorf("types %v: persisted owasp_coverage %s from a SCAN agent's result; only the owasp agent may send it",
				types, a.OwaspCoverage)
		}
	}
}

func TestOtherEditionCoverageManifestCleared(t *testing.T) {
	// The mapping is 2025, the manifest claims 2021: its category ids do not
	// correspond, so its counts cannot be recounted — and must not be
	// persisted as sent, claiming categories "found" no label backs.
	owasp := newScriptedAgent(t, owaspMappingResult(t, "2025", nil, map[string][]mappingCat{"CWE-798": {catA07}},
		map[string]interface{}{"owasp_coverage": agentManifestFor("2021", catA05)}))
	cwe := newScriptedAgent(t, mappingCWEResult)
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "owasp": owasp})

	a := h.run(t, []string{"cwe", "owasp"}, nil)

	cov := coverageOf(t, a)
	for _, c := range cov.Categories {
		if c.FoundCount != 0 || len(c.FoundCWEs) != 0 || c.Status != "clean-or-undetected" {
			t.Errorf("%s: found_count=%d found_cwes=%v status=%q from an other-edition manifest; want it cleared",
				c.ID, c.FoundCount, c.FoundCWEs, c.Status)
		}
	}
	if len(cov.UnmappedCWEs) != 0 || cov.UnmappedCount != 0 {
		t.Errorf("unmapped = %v (%d), want cleared", cov.UnmappedCWEs, cov.UnmappedCount)
	}
}

func TestZeroPaddedCWEIsLabelledCanonically(t *testing.T) {
	// The agent parses "CWE-089" as 89; the backend must label and count it
	// as CWE-89, on the finding, in the manifest and on the lineage row.
	cwe := newScriptedAgent(t, sevResult(t, nil, sevRow{"high", "CWE-089", "SQL injection", "db.go", 10}))
	owasp := newScriptedAgent(t, owaspMappingResult(t, "2025", nil, map[string][]mappingCat{"CWE-89": {catA05}},
		map[string]interface{}{"owasp_coverage": agentManifestFor("2025", catA05)}))
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "owasp": owasp})

	a := h.run(t, []string{"cwe", "owasp"}, nil)

	want := []model.ComplianceLabel{owaspLabel("2025", catA05, "CWE-89")}
	if got := labelsOf(t, a, "CWE-089"); !reflect.DeepEqual(got, want) {
		t.Errorf("labels = %+v, want %+v", got, want)
	}
	cov := coverageOf(t, a)
	if c := coverageCat(t, cov, "A05"); !reflect.DeepEqual(c.FoundCWEs, []string{"CWE-89"}) {
		t.Errorf("A05 found_cwes = %v, want [CWE-89]", c.FoundCWEs)
	}
	if len(cov.UnmappedCWEs) != 0 {
		t.Errorf("unmapped = %v, want none: CWE-089 IS mapped", cov.UnmappedCWEs)
	}
	rows := h.waitLineage(t, "the cwe row", func(r []labelledLineageRow) bool { return len(rowsOfAgent(r, "cwe")) == 1 })
	if got := rowsOfAgent(rows, "cwe")[0].ComplianceLabels; !reflect.DeepEqual(got, map[string][]string{"owasp:2025": {"A05"}}) {
		t.Errorf("lineage labels = %v, want owasp:2025 [A05]", got)
	}
}

// seedOwaspLineageRow writes the OWASP lineage row a pre-0096 backend left
// behind — the only way one can exist now that a 0096 backend never writes
// lineage for a mapper agent (M1). It clones an existing row of the same
// source (so target key, source path and provenance are exactly what the
// running backend computes) as an agent_type=owasp copy with its own
// fingerprint and ref. Written straight to the SQLite file AFTER startup, so
// the one-shot retirement (§6.3) has already run and leaves it alone.
func seedOwaspLineageRow(t *testing.T, dbPath, cloneOf string) string {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open %s: %v", dbPath, err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT name FROM pragma_table_info('finding_lineage')`)
	if err != nil {
		t.Fatalf("read lineage columns: %v", err)
	}
	var cols, sel []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		cols = append(cols, c)
		switch c {
		case "id":
			sel = append(sel, "?")
		case "agent_type":
			sel = append(sel, "'owasp'")
		case "fingerprint":
			sel = append(sel, "'pre0096-owasp-' || fingerprint")
		case "fingerprint_v2", "compliance_labels", "merged_into":
			sel = append(sel, "NULL")
		case "category":
			sel = append(sel, "'A07'")
		case "title":
			sel = append(sel, "'[A07] ' || title")
		case "ref_number":
			sel = append(sel, "(SELECT COALESCE(MAX(ref_number), 0) + 1 FROM finding_lineage)")
		default:
			sel = append(sel, c)
		}
	}
	_ = rows.Close()
	id := uuid.NewString()
	q := `INSERT INTO finding_lineage (` + strings.Join(cols, ", ") + `) SELECT ` + strings.Join(sel, ", ") +
		` FROM finding_lineage WHERE id = ?`
	if _, err := db.Exec(q, id, cloneOf); err != nil {
		t.Fatalf("seed pre-0096 owasp lineage row: %v", err)
	}
	return id
}
