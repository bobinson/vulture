//go:build e2e

package e2e

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

// GET /api/audits/{id}/lineage — the lineage rows behind one audit's findings.
//
// THE DEFECT. The read joined findings to lineage on the v1 `fingerprint`
// alone. The lineage writer matches on EITHER identity, `fingerprint_v2`
// first (feature 0091 §7.3), and keeps the row's ORIGINAL v1 when it matches
// through v2. So a finding recognised through v2 — an OWASP re-mapping whose
// title changed, a rescan under a new mount — belongs to a row whose v1 is
// not the finding's, and the read dropped that row. The results page then
// shows "—" for the finding's ref and status, and any triage on it (a
// false_positive, an accepted_risk) is invisible.
//
// THE CONTRACT. A row is returned when a finding of the audit matches it on
// v1, or on v2 within the audit's own target and agent type. The v2 arm is
// scoped to the target because v2 is root-canonical: two codebases with the
// same relative path and check produce the same v2, and one audit must never
// surface another codebase's triage.

type auditLineageStack struct {
	base *repository.SQLiteRepo
	repo repository.LineageRepository
	svc  service.LineageService
}

func newAuditLineageStack(t *testing.T) *auditLineageStack {
	t.Helper()
	base, err := repository.NewSQLiteRepo(filepath.Join(t.TempDir(), "audit_lineage_v2.db"))
	if err != nil {
		t.Fatalf("open sqlite repo: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })
	repo := repository.NewSQLiteLineageRepo(base.DB())
	return &auditLineageStack{base: base, repo: repo, svc: service.NewLineageService(repo)}
}

const (
	v2AuditID   = "audit-lineage-v2"
	v2TargetKey = "marker:target-k"
)

// seedAudit creates the audited source (target K), a second source in another
// target, the audit, and the audit's findings.
func (s *auditLineageStack) seedAudit(t *testing.T, findings []model.Finding) {
	t.Helper()
	for _, src := range []*model.Source{
		{ID: "src-k", Type: model.SourceTypeLocal, Path: "/work/k", TargetKey: v2TargetKey},
		{ID: "src-o", Type: model.SourceTypeLocal, Path: "/work/o", TargetKey: "marker:target-o"},
	} {
		if err := s.base.CreateSource(src); err != nil {
			t.Fatalf("create source %s: %v", src.ID, err)
		}
	}
	audit := &model.Audit{ID: v2AuditID, SourceID: "src-k", Types: []string{"owasp", "cwe"},
		Status: model.AuditStatusCompleted, CreatedAt: time.Now().UTC()}
	if err := s.base.CreateAudit(audit); err != nil {
		t.Fatalf("create audit: %v", err)
	}
	if err := s.base.SaveFindings(v2AuditID, findings); err != nil {
		t.Fatalf("save findings: %v", err)
	}
}

func (s *auditLineageStack) seedRow(t *testing.T, row model.FindingLineage) string {
	t.Helper()
	if row.SourcePath == "" {
		row.SourcePath = "/work/k"
	}
	if row.TargetKey == "" {
		row.TargetKey = v2TargetKey
	}
	if row.CurrentStatus == "" {
		row.CurrentStatus = model.LineageStatusOpen
	}
	row.FirstAuditID = "audit-earlier"
	row.FirstFoundAt = time.Now().UTC()
	row.Severity = "high"
	row.Title = "Hardcoded credential"
	row.FilePath = "src/config.ts"
	if err := s.repo.UpsertLineage(&row); err != nil {
		t.Fatalf("upsert lineage %q: %v", row.Fingerprint, err)
	}
	return row.ID
}

func v2Finding(agent, v1, v2 string) model.Finding {
	return model.Finding{ID: "f-" + v1, AgentType: agent, Severity: model.SeverityHigh, Category: "A07",
		Title: "[A07] Hardcoded credential in config", FilePath: "src/config.ts",
		LineStart: 12, LineEnd: 12, Fingerprint: v1, FingerprintV2: v2}
}

func auditLineageIDs(t *testing.T, svc service.LineageService) map[string]model.FindingLineage {
	t.Helper()
	rows, err := svc.ListByAudit(v2AuditID)
	if err != nil {
		t.Fatalf("list lineage by audit: %v", err)
	}
	out := make(map[string]model.FindingLineage, len(rows))
	for _, r := range rows {
		if _, dup := out[r.ID]; dup {
			t.Fatalf("row %s returned twice", r.ID)
		}
		out[r.ID] = r
	}
	return out
}

// TestAuditLineageStillMatchesByFingerprint is the control: the v1 join that
// already worked keeps working.
func TestAuditLineageStillMatchesByFingerprint(t *testing.T) {
	s := newAuditLineageStack(t)
	s.seedAudit(t, []model.Finding{v2Finding("owasp", "fp-v1-same", "fp-v2-one")})
	id := s.seedRow(t, model.FindingLineage{Fingerprint: "fp-v1-same", FingerprintV2: "fp-v2-one", AgentType: "owasp"})

	if _, ok := auditLineageIDs(t, s.svc)[id]; !ok {
		t.Fatal("a row matching a finding of the audit on fingerprint must be returned")
	}
}

// TestAuditLineageIncludesRowsMatchedOnlyByFingerprintV2 is the defect: the
// finding's v1 differs from the row's, its v2 is the row's v2.
func TestAuditLineageIncludesRowsMatchedOnlyByFingerprintV2(t *testing.T) {
	s := newAuditLineageStack(t)
	s.seedAudit(t, []model.Finding{v2Finding("owasp", "fp-v1-new", "fp-v2-two")})
	id := s.seedRow(t, model.FindingLineage{Fingerprint: "fp-v1-old", FingerprintV2: "fp-v2-two",
		AgentType: "owasp", CurrentStatus: model.LineageStatusFalsePositive})

	got, ok := auditLineageIDs(t, s.svc)[id]
	if !ok {
		t.Fatal("a row matching a finding of the audit only on fingerprint_v2 must be returned — " +
			"otherwise its triage is invisible on the results page")
	}
	if got.CurrentStatus != model.LineageStatusFalsePositive {
		t.Fatalf("returned row lost its status: %q", got.CurrentStatus)
	}
}

// TestAuditLineageV2MatchStaysInsideTheAuditsTarget: the same v2 in another
// codebase is a different finding.
func TestAuditLineageV2MatchStaysInsideTheAuditsTarget(t *testing.T) {
	s := newAuditLineageStack(t)
	s.seedAudit(t, []model.Finding{v2Finding("owasp", "fp-v1-new", "fp-v2-shared")})
	other := s.seedRow(t, model.FindingLineage{Fingerprint: "fp-v1-elsewhere", FingerprintV2: "fp-v2-shared",
		AgentType: "owasp", SourcePath: "/work/o", TargetKey: "marker:target-o",
		CurrentStatus: model.LineageStatusFalsePositive})

	if _, ok := auditLineageIDs(t, s.svc)[other]; ok {
		t.Fatal("a v2 match in ANOTHER target must not be returned: it would show that " +
			"codebase's triage on this audit's finding")
	}
}

// TestAuditLineageV2MatchRespectsAgentType: lineage is per agent; a CWE row
// with the OWASP finding's v2 is not the OWASP finding's row.
func TestAuditLineageV2MatchRespectsAgentType(t *testing.T) {
	s := newAuditLineageStack(t)
	s.seedAudit(t, []model.Finding{v2Finding("owasp", "fp-v1-new", "fp-v2-three")})
	cweRow := s.seedRow(t, model.FindingLineage{Fingerprint: "fp-v1-cwe", FingerprintV2: "fp-v2-three", AgentType: "cwe"})

	if _, ok := auditLineageIDs(t, s.svc)[cweRow]; ok {
		t.Fatal("a v2 match under another agent type must not be returned")
	}
}

// TestAuditLineageExcludesMergedRowsMatchedByV2: a row that lost a duplicate
// merge is invisible to every read, whichever identity reaches it.
func TestAuditLineageExcludesMergedRowsMatchedByV2(t *testing.T) {
	s := newAuditLineageStack(t)
	s.seedAudit(t, []model.Finding{
		v2Finding("owasp", "fp-v1-new", "fp-v2-four"),
		v2Finding("owasp", "fp-v1-live", "fp-v2-live"),
	})
	live := s.seedRow(t, model.FindingLineage{Fingerprint: "fp-v1-live", FingerprintV2: "fp-v2-live", AgentType: "owasp"})
	merged := s.seedRow(t, model.FindingLineage{Fingerprint: "fp-v1-loser", FingerprintV2: "fp-v2-four", AgentType: "owasp"})
	if _, err := s.base.DB().Exec(`UPDATE finding_lineage SET merged_into = ? WHERE id = ?`, live, merged); err != nil {
		t.Fatalf("mark row merged: %v", err)
	}

	got := auditLineageIDs(t, s.svc)
	if _, ok := got[live]; !ok {
		t.Fatal("precondition: the live row must be returned")
	}
	if _, ok := got[merged]; ok {
		t.Fatal("a merged row must never be returned")
	}
}
