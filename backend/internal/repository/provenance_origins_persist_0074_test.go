package repository

// Feature 0074 P4, T4.9 (AC17, AC18, AC31) — SQLite half.
//
// validation.provenance_origins and validation.merged_descriptions are
// top-level keys of the finding's existing `validation` blob, written by the
// Go cross-agent merge. AC31 forbids a new column, so the blob is the ONLY
// place they live: this pins that both keys survive write and read on SQLite
// unchanged (CLAUDE.md: check every implementation, not just one). The
// Postgres twin is postgres_provenance_origins_0074_integration_test.go; the
// replay third is in internal/handler/dedup_provenance_0074_test.go.

import (
	"database/sql"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vulture/backend/internal/model"
)

// auditSeeder is the slice of both repositories the 0074 round trips need.
type auditSeeder interface {
	CreateSource(*model.Source) error
	CreateAudit(*model.Audit) error
}

// seedAuditOn creates one source and one running audit with UUID ids, which
// Postgres requires and SQLite tolerates, so the SQLite test and its Postgres
// twin share one seeding path.
func seedAuditOn(t *testing.T, repo auditSeeder) string {
	t.Helper()
	now := time.Now().UTC()
	src := &model.Source{ID: uuid.NewString(), Type: model.SourceTypeLocal, Path: "/tmp", FileCount: 1, CreatedAt: now}
	if err := repo.CreateSource(src); err != nil {
		t.Fatalf("create source: %v", err)
	}
	a := &model.Audit{
		ID: uuid.NewString(), SourceID: src.ID, Types: []string{"cwe"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusRunning,
		Scores: map[string]int{}, CreatedAt: now,
	}
	if err := repo.CreateAudit(a); err != nil {
		t.Fatalf("create audit: %v", err)
	}
	return a.ID
}

// roundTripMergeKeys writes the merge survivor and reads it back through
// GetAudit (the API and replay read path) on either repository.
func roundTripMergeKeys(t *testing.T, repo interface {
	auditSeeder
	SaveFindings(string, []model.Finding) error
	GetAudit(string) (*model.Audit, error)
}) {
	t.Helper()
	auditID := seedAuditOn(t, repo)
	if err := repo.SaveFindings(auditID, []model.Finding{provenanceOriginsFinding0074(uuid.NewString(), auditID)}); err != nil {
		t.Fatalf("save: %v", err)
	}
	a, err := repo.GetAudit(auditID)
	if err != nil || a == nil {
		t.Fatalf("get audit: %v", err)
	}
	assertMergeKeysSurvive(t, a.Findings)
}

// columnNames drains a one-column result of column names, sorted.
func columnNames(t *testing.T, rows *sql.Rows, err error) []string {
	t.Helper()
	if err != nil {
		t.Fatalf("read findings columns: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// assertNoNewFindingsColumn is AC31: 0074 adds no persisted column. Both keys
// live in the existing validation blob, so the findings table's column set
// must be exactly what it was before the feature.
func assertNoNewFindingsColumn(t *testing.T, got, before []string) {
	t.Helper()
	if !reflect.DeepEqual(got, before) {
		t.Errorf("AC31: the findings table's columns changed (no new persisted column is allowed):\n got %v\nwant %v", got, before)
	}
}

// mergedValidation0074 is a merge survivor's validation blob carrying both
// 0074 keys, including a truncated entry and the multibyte text a byte cap
// must not corrupt.
func mergedValidation0074() map[string]interface{} {
	return map[string]interface{}{
		"status": "likely", "confidence": 0.7,
		"checks": []interface{}{
			map[string]interface{}{"id": "cross_agent", "result": "merged", "weight": 0.1},
		},
		"provenance_origins": []interface{}{"skill", "llm", "llm_l5_verified"},
		"merged_descriptions": []interface{}{
			map[string]interface{}{"agent_type": "cwe", "provenance": "llm", "description": "uid flows into the query — sin parametrizar"},
			map[string]interface{}{"agent_type": "asvs", "provenance": "llm", "description": strings.Repeat("x", 2040) + "…", "truncated": true},
		},
	}
}

func provenanceOriginsFinding0074(id, auditID string) model.Finding {
	return model.Finding{
		ID: id, AuditID: auditID, AgentType: "cwe", Title: "SQL injection",
		Category: "CWE-89", FilePath: "src/db.py", LineStart: 42, LineEnd: 42,
		Severity: model.SeverityHigh, Provenance: "skill",
		ValidationStatus: "likely", ValidationConfidence: 0.7,
		Validation: mergedValidation0074(),
	}
}

// keysAsJSON projects the two 0074 keys through JSON, as both repos store them.
func keysAsJSON(t *testing.T, v map[string]interface{}) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"provenance_origins":  v["provenance_origins"],
		"merged_descriptions": v["merged_descriptions"],
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := map[string]interface{}{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// assertMergeKeysSurvive is shared by the SQLite test and the Postgres twin.
func assertMergeKeysSurvive(t *testing.T, got []model.Finding) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("want 1 row back, got %d — nothing else here proves anything", len(got))
	}
	want := keysAsJSON(t, mergedValidation0074())
	if have := keysAsJSON(t, got[0].Validation); !reflect.DeepEqual(have, want) {
		t.Errorf("0074 merge keys did not survive the round trip:\n got %v\nwant %v", have, want)
	}
	if got[0].Validation["status"] != "likely" {
		t.Errorf("the merge keys cost the rest of the blob: status=%v", got[0].Validation["status"])
	}
}

// T4.9 / AC31: write then read through GetAudit (the API and replay read path).
func TestSQLiteProvenanceOriginsAndMergedDescriptionsRoundTrip_0074(t *testing.T) {
	roundTripMergeKeys(t, newTestSQLite(t))
}

// sqliteFindingsColumnsBefore0074 is the SQLite findings column set recorded
// before 0074.
var sqliteFindingsColumnsBefore0074 = []string{
	"agent_type", "audit_id", "category", "check_id", "code_snippet", "compliance_labels", "description", "file_path",
	"fingerprint", "fingerprint_v2", "id", "instance_count", "is_rollup", "line_end", "line_start", "provenance",
	"recommendation", "refs", "rolled_up_into", "severity", "title", "validation", "validation_confidence",
	"validation_status",
}

// AC31 (SQLite): no new persisted column on findings.
func TestSQLiteFindingsHasNoNewColumn_0074(t *testing.T) {
	db := newTestSQLite(t).DB()
	rows, err := db.Query(`SELECT name FROM pragma_table_info('findings')`)
	assertNoNewFindingsColumn(t, columnNames(t, rows, err), sqliteFindingsColumnsBefore0074)
}
