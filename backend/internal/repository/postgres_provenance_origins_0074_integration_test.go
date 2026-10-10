//go:build integration

package repository

// Feature 0074 P4, T4.9 (AC17, AC18, AC31) — Postgres half of the
// provenance_origins / merged_descriptions round trip. Same seeding, fixture
// and assertion as the SQLite test (provenance_origins_persist_0074_test.go).
// SKIPs when POSTGRES_TEST_DSN is unset (via newPGProvenanceRepo).

import "testing"

func TestPGProvenanceOriginsAndMergedDescriptionsRoundTrip_0074(t *testing.T) {
	roundTripMergeKeys(t, newPGProvenanceRepo(t))
}

// pgFindingsColumnsBefore0074 is the Postgres findings column set after every
// migration that predates 0074.
var pgFindingsColumnsBefore0074 = []string{
	"agent_type", "audit_id", "category", "check_id", "code_snippet", "compliance_labels", "created_at", "description", "file_path",
	"fingerprint", "fingerprint_v2", "id", "instance_count", "is_rollup", "line_end", "line_start", "provenance",
	"recommendation", "refs", "rolled_up_into", "severity", "title", "validation", "validation_confidence",
	"validation_status",
}

// AC31 (Postgres): no new persisted column on findings.
func TestPGFindingsHasNoNewColumn_0074(t *testing.T) {
	db := newPGProvenanceRepo(t).DB()
	rows, err := db.Query(`SELECT column_name FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'findings'`)
	assertNoNewFindingsColumn(t, columnNames(t, rows, err), pgFindingsColumnsBefore0074)
}
