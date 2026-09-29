//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// Feature 0096 follow-up: OWASP coverage must not count what a person triaged
// as a false positive.
//
// The persisted `audits.owasp_coverage` is the SCAN-TIME record: the manifest
// recounted from the final, labelled finding set when the run finished. A
// triage happens later, on the finding's lineage row, so a coverage card that
// reads the persisted manifest keeps reporting "A07 found" after every A07
// finding was marked false_positive.
//
// THE CONTRACT. Every endpoint that returns an audit's owasp_coverage serves
// an EFFECTIVE manifest computed at read time from the persisted manifest,
// the persisted findings' compliance_labels and the CURRENT lineage statuses:
//
//   - a finding is "triaged false positive" when its OWN lineage row — resolved
//     like the lineage writer and the findings table resolve it: agent-scoped,
//     fingerprint_v2 first, then v1, merged rows excluded — has current_status
//     false_positive. accepted_risk, resolved and the automatic likely_fp
//     validation verdict are NOT exclusions; a finding with no row is counted;
//   - per category, found_cwes = the distinct label CWEs of the category's
//     labels on findings NOT triaged false positive, found_count its length,
//     status by the scan-time rule, and a new false_positive_count = the
//     distinct triaged findings carrying a label of the category;
//   - unmapped_cwes drops a CWE once every finding categorised with it is
//     triaged false positive;
//   - the persisted column is never rewritten, so un-marking restores the
//     count, and a legacy (pre-0096) audit or a failed lineage read is served
//     the persisted manifest byte for byte.

const (
	fpcovSourceID = "src-0096-fpcov"
	fpcovPath     = "/work/fpcov"
	fpcovTarget   = "marker:fpcov-target"
	fpcovAuditID  = "audit-0096-fpcov"
)

func fpcovLabel(cat, name, cwe string) model.ComplianceLabel {
	return model.ComplianceLabel{Framework: "owasp", Edition: "2025", CategoryID: cat, CategoryName: name, CWE: cwe}
}

var (
	fpcovA05 = func(cwe string) model.ComplianceLabel { return fpcovLabel("A05", "Injection", cwe) }
	fpcovA07 = func(cwe string) model.ComplianceLabel { return fpcovLabel("A07", "Authentication Failures", cwe) }
)

// fpcovFinding is one persisted finding of the seeded audit.
type fpcovFinding struct {
	id, agent, category, v1, v2 string
	labels                      []model.ComplianceLabel
}

// fpcovRow is one lineage row; name is how a test refers to it.
type fpcovRow struct {
	name, agent, v1, v2 string
}

// fpcovCategory is one manifest category as the API returns it.
type fpcovCategory struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	MappedCount        int      `json:"mapped_count"`
	FoundCWEs          []string `json:"found_cwes"`
	FoundCount         int      `json:"found_count"`
	Status             string   `json:"status"`
	Selected           *bool    `json:"selected"`
	FalsePositiveCount *int     `json:"false_positive_count"`
}

type fpcovManifest struct {
	Edition        string          `json:"edition"`
	CWEStageStatus string          `json:"cwe_stage_status"`
	Categories     []fpcovCategory `json:"categories"`
	UnmappedCWEs   []string        `json:"unmapped_cwes"`
	UnmappedCount  *int            `json:"unmapped_count"`
}

func (m fpcovManifest) cat(t *testing.T, id string) fpcovCategory {
	t.Helper()
	for _, c := range m.Categories {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("manifest has no category %s: %+v", id, m.Categories)
	return fpcovCategory{}
}

// fpcovManifestJSON is the scan-time manifest exactly as the persist-time
// recount writes it (Go map encoding: sorted keys): A01 unselected, A05 and
// A07 found, two unmapped CWEs.
func fpcovManifestJSON(t *testing.T, a05, a07, unmapped []string) string {
	t.Helper()
	cat := func(id, name string, mapped int, found []string, selected bool) map[string]interface{} {
		status := "clean-or-undetected"
		if len(found) > 0 {
			status = "found"
		}
		c := map[string]interface{}{"id": id, "name": name, "mapped_count": mapped, "source_url": "u-" + id,
			"found_cwes": found, "found_count": len(found), "status": status}
		if !selected {
			c["selected"] = false
		}
		return c
	}
	b, err := json.Marshal(map[string]interface{}{
		"edition": "2025", "cwe_stage_status": "completed",
		"categories": []interface{}{
			cat("A01", "Broken Access Control", 40, []string{}, false),
			cat("A05", "Injection", 37, a05, true),
			cat("A07", "Authentication Failures", 36, a07, true),
		},
		"unmapped_cwes": unmapped, "unmapped_count": len(unmapped),
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return string(b)
}

// fpcovHarness is one seeded store behind a running backend.
type fpcovHarness struct {
	addr, dbPath, stored string
	rows                 map[string]string // row name -> lineage id
}

// newFPCovHarness seeds a completed audit whose findings, labels and manifest
// are what a mapping-mode run persists, plus the lineage rows, then starts the
// backend over that store.
func newFPCovHarness(t *testing.T, types []string, coverage string, findings []fpcovFinding, rows []fpcovRow) *fpcovHarness {
	t.Helper()
	cfg := testConfig(t)
	base, err := repository.NewSQLiteRepo(cfg.DBPath)
	if err != nil {
		t.Fatalf("open sqlite repo: %v", err)
	}
	if err := base.CreateSource(&model.Source{ID: fpcovSourceID, Type: model.SourceTypeLocal, Path: fpcovPath,
		TargetKey: fpcovTarget, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create source: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	audit := &model.Audit{ID: fpcovAuditID, SourceID: fpcovSourceID, Types: types,
		Status: model.AuditStatusCompleted, Scores: map[string]int{}, CreatedAt: now}
	if err := base.CreateAudit(audit); err != nil {
		t.Fatalf("create audit: %v", err)
	}
	audit.CompletedAt = &now
	audit.OwaspCoverage = json.RawMessage(coverage)
	if err := base.UpdateAudit(audit); err != nil {
		t.Fatalf("persist audit coverage: %v", err)
	}
	persisted := make([]model.Finding, 0, len(findings))
	for i, f := range findings {
		persisted = append(persisted, model.Finding{ID: f.id, AuditID: fpcovAuditID, AgentType: f.agent,
			Severity: model.SeverityHigh, Category: f.category, Title: "finding " + f.id, Description: "d",
			FilePath: "src/app.go", LineStart: 10 + i, LineEnd: 10 + i, Recommendation: "r",
			Fingerprint: f.v1, FingerprintV2: f.v2, ComplianceLabels: f.labels})
	}
	if err := base.SaveFindings(fpcovAuditID, persisted); err != nil {
		t.Fatalf("save findings: %v", err)
	}
	repo := repository.NewSQLiteLineageRepo(base.DB())
	ids := map[string]string{}
	for _, r := range rows {
		l := &model.FindingLineage{Fingerprint: r.v1, FingerprintV2: r.v2, SourcePath: fpcovPath,
			TargetKey: fpcovTarget, AgentType: r.agent, CurrentStatus: model.LineageStatusOpen,
			FirstAuditID: fpcovAuditID, FirstFoundAt: now, LatestAuditID: fpcovAuditID,
			Severity: "high", Category: "CWE-798", Title: "row " + r.name, FilePath: "src/app.go"}
		if err := repo.UpsertLineage(l); err != nil {
			t.Fatalf("upsert lineage %s: %v", r.name, err)
		}
		ids[r.name] = l.ID
	}
	_ = base.Close()

	addr, cleanup := startTestServer(t, cfg)
	t.Cleanup(cleanup)
	return &fpcovHarness{addr: addr, dbPath: cfg.DBPath, stored: coverage, rows: ids}
}

// rawCoverage is GET /api/audits/{id}'s owasp_coverage member, byte for byte.
func (h *fpcovHarness) rawCoverage(t *testing.T) json.RawMessage {
	t.Helper()
	resp, err := httpGet(h.addr, "/api/audits/"+fpcovAuditID)
	if err != nil {
		t.Fatalf("GET audit: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("GET audit: status %d", resp.StatusCode)
	}
	var body map[string]json.RawMessage
	readJSON(t, resp, &body)
	return body["owasp_coverage"]
}

func (h *fpcovHarness) coverage(t *testing.T) fpcovManifest {
	t.Helper()
	raw := h.rawCoverage(t)
	var m fpcovManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("owasp_coverage %s: %v", raw, err)
	}
	return m
}

// triage sets a lineage row's status through the real API.
func (h *fpcovHarness) triage(t *testing.T, row, status string) {
	t.Helper()
	id, ok := h.rows[row]
	if !ok {
		t.Fatalf("no seeded row %q", row)
	}
	body, _ := json.Marshal(map[string]string{"status": status})
	req, err := http.NewRequest(http.MethodPatch, "http://"+h.addr+"/api/lineage/"+id, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build PATCH: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PATCH /api/lineage/%s: %v", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH /api/lineage/%s (%s -> %s): status %d", id, row, status, resp.StatusCode)
	}
}

// storedCoverage reads the audits.owasp_coverage column straight from the store.
func (h *fpcovHarness) storedCoverage(t *testing.T) string {
	t.Helper()
	db, err := sql.Open("sqlite", h.dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	var got string
	if err := db.QueryRow(`SELECT COALESCE(owasp_coverage, '') FROM audits WHERE id = ?`, fpcovAuditID).Scan(&got); err != nil {
		t.Fatalf("read stored coverage: %v", err)
	}
	return got
}

func (h *fpcovHarness) assertStoredUnchanged(t *testing.T) {
	t.Helper()
	if got := h.storedCoverage(t); got != h.stored {
		t.Errorf("audits.owasp_coverage is the scan-time record and must never be rewritten:\n got %s\nwant %s", got, h.stored)
	}
}

type fpcovWant struct {
	found  []string
	status string
	fp     int
}

func assertFPCovCategory(t *testing.T, step string, c fpcovCategory, want fpcovWant) {
	t.Helper()
	if c.FoundCWEs == nil {
		t.Errorf("%s: %s found_cwes must always be an array, got null", step, c.ID)
	}
	if !reflect.DeepEqual(append([]string{}, c.FoundCWEs...), want.found) || c.FoundCount != len(want.found) {
		t.Errorf("%s: %s found_cwes=%v found_count=%d, want %v (%d)", step, c.ID, c.FoundCWEs, c.FoundCount,
			want.found, len(want.found))
	}
	if c.Status != want.status {
		t.Errorf("%s: %s status=%q, want %q", step, c.ID, c.Status, want.status)
	}
	if c.FalsePositiveCount == nil {
		t.Errorf("%s: %s false_positive_count must be present on a mapping-mode manifest", step, c.ID)
	} else if *c.FalsePositiveCount != want.fp {
		t.Errorf("%s: %s false_positive_count=%d, want %d", step, c.ID, *c.FalsePositiveCount, want.fp)
	}
}

// assertUntouchedCategories pins what a triage of A07 rows must never move:
// the unselected A01 (still "not selected", empty) and A05, whose only finding
// has no lineage row at all and is therefore counted.
func assertUntouchedCategories(t *testing.T, step string, m fpcovManifest) {
	t.Helper()
	a01 := m.cat(t, "A01")
	if a01.Selected == nil || *a01.Selected {
		t.Errorf("%s: A01 must keep its selected:false marker, got %v", step, a01.Selected)
	}
	assertFPCovCategory(t, step, a01, fpcovWant{found: []string{}, status: "clean-or-undetected", fp: 0})
	assertFPCovCategory(t, step, m.cat(t, "A05"), fpcovWant{found: []string{"CWE-89"}, status: "found", fp: 0})
	if a01.MappedCount != 40 || a01.Name != "Broken Access Control" {
		t.Errorf("%s: the agent's mapped_count/name must survive: %+v", step, a01)
	}
	if m.Edition != "2025" || m.CWEStageStatus != "completed" {
		t.Errorf("%s: edition/cwe_stage_status must stay the agent's: %s/%s", step, m.Edition, m.CWEStageStatus)
	}
}

// fpcovA07Store: three A07 findings over two CWEs. f-a and f-b share CWE-798;
// f-b's row is reachable ONLY through fingerprint_v2 (the writer kept the
// row's original v1); f-c carries CWE-287. f-d (A05) has no lineage row.
func fpcovA07Store(t *testing.T) *fpcovHarness {
	t.Helper()
	findings := []fpcovFinding{
		{id: "f-a", agent: "cwe", category: "CWE-798", v1: "fp-a", v2: "v2-a", labels: []model.ComplianceLabel{fpcovA07("CWE-798")}},
		{id: "f-b", agent: "cwe", category: "CWE-798", v1: "fp-b-new", v2: "v2-b", labels: []model.ComplianceLabel{fpcovA07("CWE-798")}},
		{id: "f-c", agent: "cwe", category: "CWE-287", v1: "fp-c", v2: "v2-c", labels: []model.ComplianceLabel{fpcovA07("CWE-287")}},
		{id: "f-d", agent: "cwe", category: "CWE-89", v1: "fp-d", v2: "v2-d", labels: []model.ComplianceLabel{fpcovA05("CWE-89")}},
		{id: "f-u", agent: "cwe", category: "CWE-1234", v1: "fp-u", v2: "v2-u"},
	}
	rows := []fpcovRow{
		{name: "a", agent: "cwe", v1: "fp-a", v2: "v2-a"},
		{name: "b", agent: "cwe", v1: "fp-b-original", v2: "v2-b"},
		{name: "c", agent: "cwe", v1: "fp-c", v2: "v2-c"},
		{name: "u", agent: "cwe", v1: "fp-u", v2: "v2-u"},
	}
	manifest := fpcovManifestJSON(t, []string{"CWE-89"}, []string{"CWE-287", "CWE-798"}, []string{"CWE-1234"})
	return newFPCovHarness(t, []string{"cwe", "owasp"}, manifest, findings, rows)
}

// TestOwaspCoverageExcludesTriagedFalsePositives walks the A07 category from
// found to none and back, one triage at a time.
func TestOwaspCoverageExcludesTriagedFalsePositives(t *testing.T) {
	h := fpcovA07Store(t)
	both := []string{"CWE-287", "CWE-798"}

	steps := []struct {
		name   string
		row    string
		status string
		want   fpcovWant
	}{
		{"baseline, nothing triaged", "", "", fpcovWant{both, "found", 0}},
		// f-b still carries CWE-798, so the CWE stays found.
		{"f-a false positive", "a", "false_positive", fpcovWant{both, "found", 1}},
		// f-b's row is reached only through fingerprint_v2: a v1-keyed resolver
		// would find no row for it and keep counting CWE-798.
		{"f-b false positive (v2-only row)", "b", "false_positive", fpcovWant{[]string{"CWE-287"}, "found", 2}},
		{"f-c false positive: every A07 finding triaged", "c", "false_positive",
			fpcovWant{[]string{}, "clean-or-undetected", 3}},
		{"f-a reopened", "a", "open", fpcovWant{[]string{"CWE-798"}, "found", 2}},
		{"f-b reopened", "b", "open", fpcovWant{[]string{"CWE-798"}, "found", 1}},
		{"f-c reopened: fully restored", "c", "open", fpcovWant{both, "found", 0}},
	}
	for _, s := range steps {
		if s.row != "" {
			h.triage(t, s.row, s.status)
		}
		m := h.coverage(t)
		assertFPCovCategory(t, s.name, m.cat(t, "A07"), s.want)
		assertUntouchedCategories(t, s.name, m)
	}
	h.assertStoredUnchanged(t)
}

// TestOwaspCoverageCountsAcceptedRiskAndResolved: only false_positive says
// "this is not a weakness". An accepted risk is a real weakness someone chose
// to live with, and a resolved one was real; both stay in coverage.
func TestOwaspCoverageCountsAcceptedRiskAndResolved(t *testing.T) {
	h := fpcovA07Store(t)
	h.triage(t, "a", "accepted_risk")
	h.triage(t, "b", "resolved")
	h.triage(t, "c", "accepted_risk")
	h.triage(t, "u", "resolved")

	m := h.coverage(t)
	assertFPCovCategory(t, "accepted_risk/resolved", m.cat(t, "A07"),
		fpcovWant{[]string{"CWE-287", "CWE-798"}, "found", 0})
	assertUntouchedCategories(t, "accepted_risk/resolved", m)
	if !reflect.DeepEqual(m.UnmappedCWEs, []string{"CWE-1234"}) {
		t.Errorf("a resolved finding's CWE stays unmapped: got %v", m.UnmappedCWEs)
	}
	h.assertStoredUnchanged(t)
}

// TestOwaspCoverageResolvesEachFindingToItsOwnRow: two findings share a v1
// fingerprint but each owns a different row through fingerprint_v2. Marking
// one row must exclude exactly its finding.
func TestOwaspCoverageResolvesEachFindingToItsOwnRow(t *testing.T) {
	findings := []fpcovFinding{
		{id: "f-s1", agent: "cwe", category: "CWE-798", v1: "fp-shared", v2: "v2-s1", labels: []model.ComplianceLabel{fpcovA07("CWE-798")}},
		{id: "f-s2", agent: "cwe", category: "CWE-287", v1: "fp-shared", v2: "v2-s2", labels: []model.ComplianceLabel{fpcovA07("CWE-287")}},
		{id: "f-d", agent: "cwe", category: "CWE-89", v1: "fp-d", v2: "v2-d", labels: []model.ComplianceLabel{fpcovA05("CWE-89")}},
	}
	rows := []fpcovRow{
		{name: "s1", agent: "cwe", v1: "fp-shared", v2: "v2-s1"},
		{name: "s2", agent: "cwe", v1: "fp-other", v2: "v2-s2"},
	}
	manifest := fpcovManifestJSON(t, []string{"CWE-89"}, []string{"CWE-287", "CWE-798"}, []string{})
	h := newFPCovHarness(t, []string{"cwe", "owasp"}, manifest, findings, rows)

	h.triage(t, "s1", "false_positive")
	m := h.coverage(t)
	// A v1 resolver would send f-s2 (v1 fp-shared) to row s1 and drop CWE-287 too.
	assertFPCovCategory(t, "s1 false positive", m.cat(t, "A07"), fpcovWant{[]string{"CWE-287"}, "found", 1})

	h.triage(t, "s1", "open")
	h.triage(t, "s2", "false_positive")
	m = h.coverage(t)
	assertFPCovCategory(t, "s2 false positive", m.cat(t, "A07"), fpcovWant{[]string{"CWE-798"}, "found", 1})
	assertUntouchedCategories(t, "shared v1", m)
	h.assertStoredUnchanged(t)
}

// TestOwaspCoverageDropsAnUnmappedCWEOnlyWhenAllItsFindingsAreFalsePositives:
// an unmapped CWE is a claim that the scan found a weakness the edition does
// not map. It is withdrawn once every finding categorised with it is triaged
// false positive, and not before.
func TestOwaspCoverageDropsAnUnmappedCWEOnlyWhenAllItsFindingsAreFalsePositives(t *testing.T) {
	findings := []fpcovFinding{
		{id: "f-u1", agent: "cwe", category: "CWE-1234", v1: "fp-u1", v2: "v2-u1"},
		{id: "f-u2", agent: "cwe", category: "CWE-1234", v1: "fp-u2", v2: "v2-u2"},
		{id: "f-w", agent: "cwe", category: "CWE-5555", v1: "fp-w", v2: "v2-w"},
		{id: "f-d", agent: "cwe", category: "CWE-89", v1: "fp-d", v2: "v2-d", labels: []model.ComplianceLabel{fpcovA05("CWE-89")}},
	}
	rows := []fpcovRow{
		{name: "u1", agent: "cwe", v1: "fp-u1", v2: "v2-u1"},
		{name: "u2", agent: "cwe", v1: "fp-u2", v2: "v2-u2"},
		{name: "w", agent: "cwe", v1: "fp-w", v2: "v2-w"},
	}
	manifest := fpcovManifestJSON(t, []string{"CWE-89"}, []string{}, []string{"CWE-1234", "CWE-5555"})
	h := newFPCovHarness(t, []string{"cwe", "owasp"}, manifest, findings, rows)

	unmapped := func(step string, want []string) {
		t.Helper()
		m := h.coverage(t)
		count := -1
		if m.UnmappedCount != nil {
			count = *m.UnmappedCount
		}
		if !reflect.DeepEqual(append([]string{}, m.UnmappedCWEs...), want) || count != len(want) {
			t.Errorf("%s: unmapped_cwes=%v unmapped_count=%d, want %v (%d)", step, m.UnmappedCWEs, count, want, len(want))
		}
	}
	unmapped("baseline", []string{"CWE-1234", "CWE-5555"})
	h.triage(t, "u1", "false_positive")
	unmapped("one of two CWE-1234 findings triaged", []string{"CWE-1234", "CWE-5555"})
	h.triage(t, "u2", "false_positive")
	unmapped("both CWE-1234 findings triaged", []string{"CWE-5555"})
	h.triage(t, "u2", "open")
	unmapped("one reopened", []string{"CWE-1234", "CWE-5555"})
	h.assertStoredUnchanged(t)
}

// TestOwaspCoverageLeavesAPre0096AuditUntouched: a pre-0096 audit has OWASP
// copy rows (agent_type owasp) and no labels. Its manifest is the agent's own,
// not a label recount, so there is nothing to recount it from; it is served
// exactly as stored, whatever its rows' triage says.
func TestOwaspCoverageLeavesAPre0096AuditUntouched(t *testing.T) {
	findings := []fpcovFinding{
		{id: "f-cwe", agent: "cwe", category: "CWE-798", v1: "fp-cwe", v2: "v2-cwe"},
		{id: "f-copy", agent: "owasp", category: "A07", v1: "fp-copy", v2: "v2-copy"},
	}
	rows := []fpcovRow{
		{name: "cwe", agent: "cwe", v1: "fp-cwe", v2: "v2-cwe"},
		{name: "copy", agent: "owasp", v1: "fp-copy", v2: "v2-copy"},
	}
	// The legacy agent's manifest, verbatim (its own key order, not Go's).
	manifest := `{"edition":"2025","cwe_stage_status":"completed","categories":[{"id":"A07",` +
		`"name":"Authentication Failures","mapped_count":36,"found_cwes":["CWE-798"],"found_count":1,` +
		`"status":"found","source_url":"u"}],"unmapped_cwes":[],"unmapped_count":0}`
	h := newFPCovHarness(t, []string{"cwe", "owasp"}, manifest, findings, rows)
	h.triage(t, "cwe", "false_positive")
	h.triage(t, "copy", "false_positive")

	if got := h.rawCoverage(t); string(got) != manifest {
		t.Errorf("a pre-0096 audit's coverage must be served byte for byte:\n got %s\nwant %s", got, manifest)
	}
	h.assertStoredUnchanged(t)
}

// TestOwaspCoverageLeavesAPre0096AuditWithoutCopiesUntouched: a pre-0096 run
// whose OWASP agent mapped nothing wrote no copy rows and claims no category
// found, yet it still listed the CWEs it could not place. Nothing about its
// rows says "mapping mode"; its manifest is the agent's own, persisted as the
// agent sent it. It is served byte for byte — no false_positive_count added,
// no unmapped CWE withdrawn — before and after its only finding is triaged.
func TestOwaspCoverageLeavesAPre0096AuditWithoutCopiesUntouched(t *testing.T) {
	findings := []fpcovFinding{
		{id: "f-u", agent: "cwe", category: "CWE-1234", v1: "fp-u", v2: "v2-u"},
	}
	rows := []fpcovRow{{name: "u", agent: "cwe", v1: "fp-u", v2: "v2-u"}}
	// The legacy agent's manifest as its SSE frame carried it: Python's
	// json.dumps, default separators, the agent's own key order.
	manifest := `{"edition": "2025", "cwe_stage_status": "completed", "categories": [{"id": "A07", ` +
		`"name": "Authentication Failures", "mapped_count": 36, "found_cwes": [], "found_count": 0, ` +
		`"status": "clean-or-undetected", "source_url": "u"}], "unmapped_cwes": ["CWE-1234"], "unmapped_count": 1}`
	h := newFPCovHarness(t, []string{"cwe", "owasp"}, manifest, findings, rows)
	// The response encoder compacts every embedded JSON value (whitespace
	// only); key order and content are what the stored record says.
	var served bytes.Buffer
	if err := json.Compact(&served, []byte(manifest)); err != nil {
		t.Fatalf("compact manifest: %v", err)
	}
	want := served.String()

	if got := h.rawCoverage(t); string(got) != want {
		t.Errorf("untriaged: a pre-0096 audit's coverage must be served as stored:\n got %s\nwant %s", got, want)
	}
	h.triage(t, "u", "false_positive")
	if got := h.rawCoverage(t); string(got) != want {
		t.Errorf("triaged: a pre-0096 audit's coverage must be served as stored:\n got %s\nwant %s", got, want)
	}
	h.assertStoredUnchanged(t)
}

// TestOwaspCoverageServesThePersistedManifestWhenLineageCannotBeRead: the
// effective manifest is an enrichment. When the lineage read fails, the
// audit is still served — with the scan-time manifest, not an error and not
// a manifest that silently counts nothing.
func TestOwaspCoverageServesThePersistedManifestWhenLineageCannotBeRead(t *testing.T) {
	h := fpcovA07Store(t)
	h.triage(t, "a", "false_positive")
	h.triage(t, "b", "false_positive")
	if got := h.coverage(t).cat(t, "A07").FoundCWEs; !reflect.DeepEqual(got, []string{"CWE-287"}) {
		t.Fatalf("precondition: triage must apply while lineage is readable, got %v", got)
	}

	db, err := sql.Open("sqlite", h.dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`ALTER TABLE finding_lineage RENAME TO finding_lineage_unreadable`); err != nil {
		t.Fatalf("break the lineage table: %v", err)
	}

	if got := h.rawCoverage(t); string(got) != h.stored {
		t.Errorf("a failed lineage read must degrade to the persisted manifest:\n got %s\nwant %s", got, h.stored)
	}
	h.assertStoredUnchanged(t)
}

// TestOwaspCoverageReplayServesTheEffectiveManifest: the SSE replay of a
// finished audit re-emits owasp_coverage on a synthesized owasp snapshot; it
// must carry the same effective manifest GET /api/audits/{id} serves.
func TestOwaspCoverageReplayServesTheEffectiveManifest(t *testing.T) {
	h := fpcovA07Store(t)
	h.triage(t, "c", "false_positive")

	resp, err := httpGet(h.addr, "/api/audits/"+fpcovAuditID+"/stream")
	if err != nil {
		t.Fatalf("GET stream: %v", err)
	}
	defer resp.Body.Close()
	var replayed json.RawMessage
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var evt struct {
			Type      string          `json:"type"`
			AgentType string          `json:"agentType"`
			Snapshot  json.RawMessage `json:"snapshot"`
		}
		if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &evt) != nil || evt.AgentType != "owasp" {
			continue
		}
		var snap struct {
			OwaspCoverage json.RawMessage `json:"owasp_coverage"`
		}
		if json.Unmarshal(evt.Snapshot, &snap) == nil && len(snap.OwaspCoverage) > 0 {
			replayed = snap.OwaspCoverage
		}
	}
	if len(replayed) == 0 {
		t.Fatal("the replay carried no owasp_coverage")
	}
	var m fpcovManifest
	if err := json.Unmarshal(replayed, &m); err != nil {
		t.Fatalf("replayed owasp_coverage %s: %v", replayed, err)
	}
	assertFPCovCategory(t, "replay", m.cat(t, "A07"), fpcovWant{[]string{"CWE-798"}, "found", 1})
	if got := h.rawCoverage(t); !bytes.Equal(got, replayed) {
		t.Errorf("replay and GET must serve the same manifest:\n replay %s\n    get %s", replayed, got)
	}
	h.assertStoredUnchanged(t)
}

// TestOwaspCoverageServesThePersistedManifestWhenFindingsCannotBeRead: the
// recount is only as good as the findings it is given, and the audit read
// swallows a findings-read error — the audit is served with no findings. A
// manifest recounted from nothing would claim every category clean; it must
// instead be the scan-time manifest, byte for byte, whatever the triage.
func TestOwaspCoverageServesThePersistedManifestWhenFindingsCannotBeRead(t *testing.T) {
	h := fpcovA07Store(t)
	h.triage(t, "c", "false_positive")
	if got := h.coverage(t).cat(t, "A07").FoundCWEs; !reflect.DeepEqual(got, []string{"CWE-798"}) {
		t.Fatalf("precondition: triage must apply while findings are readable, got %v", got)
	}

	db, err := sql.Open("sqlite", h.dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	// One row whose line_start is not an integer fails the findings scan.
	if _, err := db.Exec(`UPDATE findings SET line_start = 'unreadable' WHERE id = 'f-d'`); err != nil {
		t.Fatalf("break a findings row: %v", err)
	}

	if got := h.rawCoverage(t); string(got) != h.stored {
		t.Errorf("an unreadable finding set must degrade to the persisted manifest, not a recount of nothing:\n got %s\nwant %s", got, h.stored)
	}
	h.assertStoredUnchanged(t)
}
