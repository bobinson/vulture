//go:build integration

// Feature 0096 §4.3 — Postgres round-trip of `compliance_labels` (migration
// 030) on `findings` and `finding_lineage`. The SQLite twin is the E2E file
// test/e2e/compliance_labels_storage_test.go; the two dialects store the
// column differently (JSONB here, TEXT there) and bind it through separate
// hand-written statements, so each is executed against a real database.
package repository

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vulture/backend/internal/model"
)

// TestPGComplianceLabelsRoundTripOnFindings: labels written by SaveFindings
// read back unchanged through GetAudit; a finding with none is NULL in the
// column and nil on the struct. The column is JSONB, so the stored value is a
// real JSON array, not a string that happens to contain one.
func TestPGComplianceLabelsRoundTripOnFindings(t *testing.T) {
	_, owner, fx := newPGLineageRepo(t)
	auditID := fx.audit(t, owner, "labels")
	labelled, bare := uuid.NewString(), uuid.NewString()
	want := []model.ComplianceLabel{
		{Framework: "owasp", Edition: "2025", CategoryID: "A07",
			CategoryName: "Authentication Failures", CWE: "CWE-798"},
		{Framework: "owasp", Edition: "2025", CategoryID: "A02",
			CategoryName: "Security Misconfiguration", CWE: "CWE-798"},
	}
	findings := []model.Finding{
		{ID: labelled, AuditID: auditID, AgentType: "cwe", Severity: model.SeverityHigh,
			Category: "CWE-798", Title: "Hardcoded credential", FilePath: "a.go",
			ComplianceLabels: want},
		{ID: bare, AuditID: auditID, AgentType: "cwe", Severity: model.SeverityLow,
			Category: "CWE-1004", Title: "Cookie without HttpOnly", FilePath: "b.go"},
	}
	if err := owner.SaveFindings(auditID, findings); err != nil {
		t.Fatalf("save findings: %v", err)
	}

	got, err := owner.GetAudit(auditID)
	if err != nil || got == nil {
		t.Fatalf("get audit: %v (audit=%v)", err, got)
	}
	byID := map[string]model.Finding{}
	for _, f := range got.Findings {
		byID[f.ID] = f
	}
	if !reflect.DeepEqual(byID[labelled].ComplianceLabels, want) {
		t.Errorf("labels did not round-trip: got %+v, want %+v", byID[labelled].ComplianceLabels, want)
	}
	if byID[bare].ComplianceLabels != nil {
		t.Errorf("an unlabelled finding must read back nil, got %+v", byID[bare].ComplianceLabels)
	}

	var kind string
	if err := owner.DB().QueryRow(
		`SELECT jsonb_typeof(compliance_labels) FROM findings WHERE id = $1`, labelled).Scan(&kind); err != nil {
		t.Fatalf("probe jsonb type: %v", err)
	}
	if kind != "array" {
		t.Errorf("findings.compliance_labels stored as jsonb %q, want array", kind)
	}
	var isNull bool
	if err := owner.DB().QueryRow(
		`SELECT compliance_labels IS NULL FROM findings WHERE id = $1`, bare).Scan(&isNull); err != nil {
		t.Fatalf("probe null: %v", err)
	}
	if !isNull {
		t.Error("an unlabelled finding must store NULL, not an empty array")
	}
}

// TestPGComplianceLabelsRoundTripOnLineage: the per-edition map written by
// UpsertLineage reads back through every lineage reader, NULL stays NULL, and
// a re-sighting replaces only the `framework:edition` keys it carries (§4.2) —
// both through the ON CONFLICT branch and through the target-identity
// recovery branch, which must stay the same operation.
func TestPGComplianceLabelsRoundTripOnLineage(t *testing.T) {
	repo, owner, fx := newPGLineageRepo(t)
	first := fx.audit(t, owner, "first")
	sight := func(labels map[string][]string) *model.FindingLineage {
		t.Helper()
		l := &model.FindingLineage{
			Fingerprint: "fp-labels", SourcePath: "/repo", AgentType: "cwe",
			CurrentStatus: model.LineageStatusOpen, FirstAuditID: first,
			FirstFoundAt: time.Now().UTC(), LatestAuditID: first,
			Severity: "high", Category: "CWE-798", Title: "Hardcoded credential",
			FilePath: "a.go", ComplianceLabels: labels,
		}
		if err := repo.UpsertLineage(l); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		got, err := repo.GetLineage(l.ID)
		if err != nil || got == nil {
			t.Fatalf("get lineage %s: %v (row=%v)", l.ID, err, got)
		}
		return got
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
	var row *model.FindingLineage
	for _, s := range steps {
		row = sight(s.carry)
		if !reflect.DeepEqual(row.ComplianceLabels, s.want) {
			t.Fatalf("%s: labels = %v, want %v", s.name, row.ComplianceLabels, s.want)
		}
	}

	// The multi-row readers share the scanner; one of them is enough to prove
	// the column is in the shared SELECT list and not only in GetLineage.
	active, err := repo.GetActiveBySourcePath("/repo", "cwe")
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if len(active) != 1 || !reflect.DeepEqual(active[0].ComplianceLabels, row.ComplianceLabels) {
		t.Errorf("GetActiveBySourcePath labels = %+v, want one row with %v", active, row.ComplianceLabels)
	}

	var raw []byte
	if err := owner.DB().QueryRow(
		`SELECT compliance_labels FROM finding_lineage WHERE id = $1`, row.ID).Scan(&raw); err != nil {
		t.Fatalf("probe stored labels: %v", err)
	}
	var stored map[string][]string
	if err := json.Unmarshal(raw, &stored); err != nil || !reflect.DeepEqual(stored, row.ComplianceLabels) {
		t.Errorf("stored jsonb = %s (%v), want %v", raw, err, row.ComplianceLabels)
	}

	bare := pgLineage(t, repo, owner, fx, "fp-bare", model.LineageStatusOpen)
	var isNull bool
	if err := owner.DB().QueryRow(
		`SELECT compliance_labels IS NULL FROM finding_lineage WHERE id = $1`, bare.ID).Scan(&isNull); err != nil {
		t.Fatalf("probe null: %v", err)
	}
	if !isNull {
		t.Error("an unlabelled lineage row must store NULL, not an empty object")
	}
	if got, _ := repo.GetLineage(bare.ID); got == nil || got.ComplianceLabels != nil {
		t.Errorf("an unlabelled lineage row must read back nil, got %+v", got)
	}
}

// TestPGComplianceLabelsMergeOnTheTargetConflictBranch: a re-sighting under
// another mount reaches the row through updateOnTargetConflict, not ON
// CONFLICT. It must merge labels exactly as the ordinary branch does — a
// column refreshed on one branch and not the other is refreshed on some scans
// and not others.
func TestPGComplianceLabelsMergeOnTheTargetConflictBranch(t *testing.T) {
	repo, owner, fx := newPGLineageRepo(t)
	first := fx.audit(t, owner, "first")
	row := func(fingerprint, sourcePath string, labels map[string][]string) *model.FindingLineage {
		return &model.FindingLineage{
			Fingerprint: fingerprint, SourcePath: sourcePath, AgentType: "cwe",
			CurrentStatus: model.LineageStatusOpen, FirstAuditID: first,
			FirstFoundAt: time.Now().UTC(), LatestAuditID: first,
			Severity: "high", Category: "CWE-798", Title: "Hardcoded credential",
			FilePath: "src/api.py", FingerprintV2: "fpv2-labels",
			TargetKey: "git:github.com/acme/labels", ComplianceLabels: labels,
		}
	}
	original := row("fp-native", "/home/x/labels", map[string][]string{"owasp:2025": {"A07"}})
	if err := repo.UpsertLineage(original); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	second := row("fp-docker", "/mnt/source/labels", map[string][]string{"owasp:2021": {"A02"}})
	if err := repo.UpsertLineage(second); err != nil {
		t.Fatalf("colliding upsert: %v", err)
	}
	if second.ID != original.ID {
		t.Fatalf("the colliding write must resolve to the existing row: got %q, want %q", second.ID, original.ID)
	}
	third := row("fp-docker-2", "/mnt/other/labels", nil)
	if err := repo.UpsertLineage(third); err != nil {
		t.Fatalf("unlabelled colliding upsert: %v", err)
	}
	got, err := repo.GetLineage(original.ID)
	if err != nil || got == nil {
		t.Fatalf("re-read: %v", err)
	}
	want := map[string][]string{"owasp:2025": {"A07"}, "owasp:2021": {"A02"}}
	if !reflect.DeepEqual(got.ComplianceLabels, want) {
		t.Errorf("labels after the target-conflict branch = %v, want %v", got.ComplianceLabels, want)
	}
}

// TestPGComplianceLabelsWithNULPersistTheWholeChunk: a NUL byte in any label
// string is valid JSON (`\u0000`) but a value Postgres jsonb refuses, and
// SaveFindings writes a chunk in ONE statement — so one such label would drop
// every finding in the chunk, while SQLite accepted the same value. The codec
// strips it at the storage boundary, exactly as dbSafeText does for the text
// columns, on findings and on the lineage map's keys and category ids alike.
func TestPGComplianceLabelsWithNULPersistTheWholeChunk(t *testing.T) {
	repo, owner, fx := newPGLineageRepo(t)
	auditID := fx.audit(t, owner, "labels-nul")
	dirty, clean := uuid.NewString(), uuid.NewString()
	findings := []model.Finding{
		{ID: dirty, AuditID: auditID, AgentType: "cwe", Severity: model.SeverityHigh,
			Category: "CWE-798", Title: "Hardcoded credential", FilePath: "a.go",
			ComplianceLabels: []model.ComplianceLabel{{Framework: "ow\x00asp", Edition: "20\x0025",
				CategoryID: "A0\x007", CategoryName: "Authentication\x00 Failures", CWE: "CWE-\x00798"}}},
		{ID: clean, AuditID: auditID, AgentType: "cwe", Severity: model.SeverityLow,
			Category: "CWE-1004", Title: "Cookie without HttpOnly", FilePath: "b.go"},
	}
	if err := owner.SaveFindings(auditID, findings); err != nil {
		t.Fatalf("a NUL inside a label must not fail the chunk: %v", err)
	}
	got, err := owner.GetAudit(auditID)
	if err != nil || got == nil {
		t.Fatalf("get audit: %v (audit=%v)", err, got)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("both findings of the chunk must persist, got %d", len(got.Findings))
	}
	want := []model.ComplianceLabel{{Framework: "owasp", Edition: "2025",
		CategoryID: "A07", CategoryName: "Authentication Failures", CWE: "CWE-798"}}
	for _, f := range got.Findings {
		if f.ID == dirty && !reflect.DeepEqual(f.ComplianceLabels, want) {
			t.Errorf("sanitised labels = %+v, want %+v", f.ComplianceLabels, want)
		}
	}

	first := fx.audit(t, owner, "labels-nul-lineage")
	l := &model.FindingLineage{
		Fingerprint: "fp-labels-nul", SourcePath: "/repo-nul", AgentType: "cwe",
		CurrentStatus: model.LineageStatusOpen, FirstAuditID: first,
		FirstFoundAt: time.Now().UTC(), LatestAuditID: first,
		Severity: "high", Category: "CWE-798", Title: "Hardcoded credential", FilePath: "a.go",
		ComplianceLabels: map[string][]string{"owasp:\x002025": {"A\x0007"}},
	}
	if err := repo.UpsertLineage(l); err != nil {
		t.Fatalf("a NUL inside a lineage label key or id must not fail the upsert: %v", err)
	}
	row, err := repo.GetLineage(l.ID)
	if err != nil || row == nil {
		t.Fatalf("get lineage: %v (row=%v)", err, row)
	}
	if want := map[string][]string{"owasp:2025": {"A07"}}; !reflect.DeepEqual(row.ComplianceLabels, want) {
		t.Errorf("sanitised lineage labels = %v, want %v", row.ComplianceLabels, want)
	}
}
