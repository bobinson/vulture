//go:build e2e

package e2e

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// Feature 0096 §4: compliance labels are stored ON the finding and, per
// `framework:edition`, on its lineage row — they replace the OWASP copy rows.
// This is the SQLite half of the storage contract (the Postgres half is
// postgres_compliance_labels_integration_test.go): what is written is what a
// client reads back through the real HTTP API, and "no labels" is NULL in the
// store and ABSENT on the wire, never `[]` or `{}`.
//
// The lineage upsert is also pinned to the §4.2 rule at the storage layer: a
// sighting replaces only the `framework:edition` keys it carries. A sighting
// with no labels (a CWE-only scan) and a sighting of another edition leave
// every other key as it was — absence never clears.

const (
	labelsAuditID  = "audit-0096-labels"
	labelsSourceID = "src-0096-labels"
)

var a07 = model.ComplianceLabel{Framework: "owasp", Edition: "2025",
	CategoryID: "A07", CategoryName: "Authentication Failures", CWE: "CWE-798"}

func labelledFindings() []model.Finding {
	base := func(id, category string) model.Finding {
		return model.Finding{ID: id, AuditID: labelsAuditID, AgentType: "cwe",
			Severity: model.SeverityHigh, Category: category, Title: "t " + id,
			Description: "d", FilePath: "src/app.go", LineStart: 3, LineEnd: 3,
			Recommendation: "r", Fingerprint: "fp-" + id}
	}
	labelled := base("f-labelled", "CWE-798")
	labelled.ComplianceLabels = []model.ComplianceLabel{a07}
	return []model.Finding{labelled, base("f-bare", "CWE-1004")}
}

func labelsLineage(fingerprint string, labels map[string][]string) *model.FindingLineage {
	return &model.FindingLineage{Fingerprint: fingerprint, SourcePath: "/work/labels",
		AgentType: "cwe", CurrentStatus: model.LineageStatusOpen,
		FirstAuditID: labelsAuditID, FirstFoundAt: time.Now().UTC(), LatestAuditID: labelsAuditID,
		Severity: "high", Category: "CWE-798", Title: "Hardcoded credential",
		FilePath: "src/app.go", ComplianceLabels: labels}
}

// seedLabelledStore writes the fixture through the real SQLite repositories and
// returns the ids of the labelled and the unlabelled lineage rows.
func seedLabelledStore(t *testing.T, dbPath string) (labelled, bare string) {
	t.Helper()
	base, err := repository.NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("open sqlite repo: %v", err)
	}
	defer base.Close()
	if err := base.CreateSource(&model.Source{ID: labelsSourceID, Type: model.SourceTypeLocal,
		Path: "/work/labels", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create source: %v", err)
	}
	if err := base.CreateAudit(&model.Audit{ID: labelsAuditID, SourceID: labelsSourceID,
		Types: []string{"cwe", "owasp"}, Status: model.AuditStatusCompleted,
		CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create audit: %v", err)
	}
	if err := base.SaveFindings(labelsAuditID, labelledFindings()); err != nil {
		t.Fatalf("save findings: %v", err)
	}
	repo := repository.NewSQLiteLineageRepo(base.DB())
	l := labelsLineage("fp-f-labelled", map[string][]string{"owasp:2025": {"A07"}})
	if err := repo.UpsertLineage(l); err != nil {
		t.Fatalf("upsert labelled lineage: %v", err)
	}
	b := labelsLineage("fp-f-bare", nil)
	if err := repo.UpsertLineage(b); err != nil {
		t.Fatalf("upsert bare lineage: %v", err)
	}
	assertStoredNull(t, base.DB(), `SELECT compliance_labels IS NULL FROM findings WHERE id = ?`, "f-bare")
	assertStoredNull(t, base.DB(), `SELECT compliance_labels IS NULL FROM finding_lineage WHERE id = ?`, b.ID)
	return l.ID, b.ID
}

func assertStoredNull(t *testing.T, db *sql.DB, query, id string) {
	t.Helper()
	var isNull bool
	if err := db.QueryRow(query, id).Scan(&isNull); err != nil {
		t.Fatalf("probe %q: %v", query, err)
	}
	if !isNull {
		t.Errorf("row %s: no labels must be stored as NULL (%s)", id, query)
	}
}

func TestSQLiteComplianceLabelsRoundTripThroughTheAPI(t *testing.T) {
	cfg := testConfig(t)
	labelledID, bareID := seedLabelledStore(t, cfg.DBPath)

	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, err := httpGet(addr, "/api/audits/"+labelsAuditID)
	if err != nil {
		t.Fatalf("GET audit: %v", err)
	}
	var audit struct {
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	readJSON(t, resp, &audit)
	byID := map[string]map[string]json.RawMessage{}
	for _, f := range audit.Findings {
		var id string
		_ = json.Unmarshal(f["id"], &id)
		byID[id] = f
	}
	var gotLabels []model.ComplianceLabel
	if err := json.Unmarshal(byID["f-labelled"]["compliance_labels"], &gotLabels); err != nil {
		t.Fatalf("f-labelled compliance_labels = %s: %v", byID["f-labelled"]["compliance_labels"], err)
	}
	if !reflect.DeepEqual(gotLabels, []model.ComplianceLabel{a07}) {
		t.Errorf("finding labels did not round-trip: got %+v, want [%+v]", gotLabels, a07)
	}
	if raw, present := byID["f-bare"]["compliance_labels"]; present {
		t.Errorf("an unlabelled finding must omit compliance_labels, got %s", raw)
	}

	lineageLabels := func(id string) (json.RawMessage, bool) {
		resp, err := httpGet(addr, "/api/lineage/"+id)
		if err != nil {
			t.Fatalf("GET lineage %s: %v", id, err)
		}
		var detail struct {
			Lineage map[string]json.RawMessage `json:"lineage"`
		}
		readJSON(t, resp, &detail)
		if detail.Lineage == nil {
			t.Fatalf("GET /api/lineage/%s returned no lineage object", id)
		}
		raw, ok := detail.Lineage["compliance_labels"]
		return raw, ok
	}
	raw, _ := lineageLabels(labelledID)
	var gotMap map[string][]string
	if err := json.Unmarshal(raw, &gotMap); err != nil {
		t.Fatalf("lineage compliance_labels = %s: %v", raw, err)
	}
	if want := map[string][]string{"owasp:2025": {"A07"}}; !reflect.DeepEqual(gotMap, want) {
		t.Errorf("lineage labels did not round-trip: got %v, want %v", gotMap, want)
	}
	if raw, present := lineageLabels(bareID); present {
		t.Errorf("an unlabelled lineage row must omit compliance_labels, got %s", raw)
	}
}

func TestSQLiteLineageLabelsReplaceOnlyTheEditionsASightingCarries(t *testing.T) {
	base, err := repository.NewSQLiteRepo(filepath.Join(t.TempDir(), "labels_merge.db"))
	if err != nil {
		t.Fatalf("open sqlite repo: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })
	repo := repository.NewSQLiteLineageRepo(base.DB())

	sight := func(labels map[string][]string) map[string][]string {
		t.Helper()
		l := labelsLineage("fp-merge", labels)
		if err := repo.UpsertLineage(l); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		got, err := repo.GetLineage(l.ID)
		if err != nil || got == nil {
			t.Fatalf("get lineage %s: %v (row=%v)", l.ID, err, got)
		}
		return got.ComplianceLabels
	}

	steps := []struct {
		name  string
		carry map[string][]string
		want  map[string][]string
	}{
		{"first sighting stores its edition",
			map[string][]string{"owasp:2025": {"A07"}},
			map[string][]string{"owasp:2025": {"A07"}}},
		{"a sighting without labels keeps them",
			nil,
			map[string][]string{"owasp:2025": {"A07"}}},
		{"another edition is added beside, not over",
			map[string][]string{"owasp:2021": {"A02", "A07"}},
			map[string][]string{"owasp:2025": {"A07"}, "owasp:2021": {"A02", "A07"}}},
		{"the same edition is replaced whole",
			map[string][]string{"owasp:2025": {"A04"}},
			map[string][]string{"owasp:2025": {"A04"}, "owasp:2021": {"A02", "A07"}}},
	}
	for _, s := range steps {
		if got := sight(s.carry); !reflect.DeepEqual(got, s.want) {
			t.Fatalf("%s: labels = %v, want %v", s.name, got, s.want)
		}
	}
}
