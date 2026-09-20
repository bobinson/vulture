//go:build e2e

package e2e

import (
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

// newLineageStack builds a real SQLite-backed lineage repository and service.
// No mocks: this exercises the persisted filter that decides which lineage rows
// a scan is allowed to close.
func newLineageStack(t *testing.T) (service.LineageService, repository.LineageRepository) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "lineage_e2e.db")
	base, err := repository.NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("open sqlite repo: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })

	lineageRepo := repository.NewSQLiteLineageRepo(base.DB())
	return service.NewLineageService(lineageRepo), lineageRepo
}

func lineageTestSource(path string) *model.Source {
	return &model.Source{
		ID:             "src-lineage-e2e",
		Type:           model.SourceTypeLocal,
		Path:           path,
		GitBranch:      "main",
		GitCommitShort: "abc1234",
	}
}

func lineageTestAudit(id string) *model.Audit {
	return &model.Audit{ID: id, SourceID: "src-lineage-e2e", Types: []string{"cwe"}}
}

func lineageTestFinding(fingerprint string) model.Finding {
	return model.Finding{
		AgentType:   "cwe",
		Severity:    model.SeverityHigh,
		Category:    "injection",
		Title:       "Command injection in build task",
		FilePath:    ".vscode/tasks.json",
		LineStart:   7,
		LineEnd:     7,
		Fingerprint: fingerprint,
	}
}

func statusOf(t *testing.T, repo repository.LineageRepository, fingerprint, sourcePath string) model.LineageStatus {
	t.Helper()
	l, err := repo.GetLineageByFingerprint(fingerprint, sourcePath, "cwe")
	if err != nil {
		t.Fatalf("get lineage by fingerprint: %v", err)
	}
	if l == nil {
		t.Fatalf("no lineage row for fingerprint %q under %q", fingerprint, sourcePath)
	}
	return l.CurrentStatus
}

// TestRegressionCanBeFixed pins scenario S12: once a finding has regressed, a
// later scan whose result no longer contains its fingerprint must close it as
// `fixed`. A lineage stuck at `regression` forever is a reporting defect — the
// row is active, so the next clean scan is entitled to close it exactly as it
// would close an `open` one.
func TestRegressionCanBeFixed(t *testing.T) {
	svc, repo := newLineageStack(t)
	srcPath := t.TempDir()
	source := lineageTestSource(srcPath)
	const fp = "fp-regression-closes"
	finding := lineageTestFinding(fp)

	// Scan 1: the finding is present -> open.
	if err := svc.ProcessAuditFindings(lineageTestAudit("audit-1"), source, []model.Finding{finding}); err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	if got := statusOf(t, repo, fp, srcPath); got != model.LineageStatusOpen {
		t.Fatalf("after scan 1: expected %q, got %q", model.LineageStatusOpen, got)
	}

	// Scan 2: the finding is gone -> fixed. The scan still reports something
	// else from the same agent, because a result carrying no finding at all for
	// an agent closes nothing (the agent never appears in the scan's agent set).
	if err := svc.ProcessAuditFindings(lineageTestAudit("audit-2"), source, []model.Finding{
		lineageTestFinding("fp-some-other-finding"),
	}); err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	if got := statusOf(t, repo, fp, srcPath); got != model.LineageStatusFixed {
		t.Fatalf("after scan 2: expected %q, got %q", model.LineageStatusFixed, got)
	}

	// Scan 3: the finding is back -> regression.
	if err := svc.ProcessAuditFindings(lineageTestAudit("audit-3"), source, []model.Finding{
		finding, lineageTestFinding("fp-some-other-finding"),
	}); err != nil {
		t.Fatalf("scan 3: %v", err)
	}
	if got := statusOf(t, repo, fp, srcPath); got != model.LineageStatusRegression {
		t.Fatalf("after scan 3: expected %q, got %q", model.LineageStatusRegression, got)
	}

	// Scan 4: the finding is gone again. THIS is the contract: a regression is
	// an active row, so its absence closes it.
	if err := svc.ProcessAuditFindings(lineageTestAudit("audit-4"), source, []model.Finding{
		lineageTestFinding("fp-some-other-finding"),
	}); err != nil {
		t.Fatalf("scan 4: %v", err)
	}
	if got := statusOf(t, repo, fp, srcPath); got != model.LineageStatusFixed {
		t.Fatalf("after scan 4: a regression absent from the result must become %q, got %q",
			model.LineageStatusFixed, got)
	}

	// And the closure is recorded on the timeline as a transition out of
	// `regression`, not out of `open`.
	l, err := repo.GetLineageByFingerprint(fp, srcPath, "cwe")
	if err != nil {
		t.Fatalf("get lineage: %v", err)
	}
	events, err := repo.GetEvents(l.ID)
	if err != nil {
		t.Fatalf("get events: %v", err)
	}
	var sawRegressionClosed bool
	for _, e := range events {
		if e.EventType == model.LineageEventFixed &&
			e.OldStatus == string(model.LineageStatusRegression) &&
			e.NewStatus == string(model.LineageStatusFixed) {
			sawRegressionClosed = true
		}
	}
	if !sawRegressionClosed {
		t.Fatalf("expected a %q event for regression -> fixed, got %+v", model.LineageEventFixed, events)
	}
}

// TestUserDecidedStatusesStayClosedToTheScanner guards the other half of the
// same filter: widening "active" to include `regression` must not make the
// scanner able to reopen or re-close statuses a human set.
func TestUserDecidedStatusesStayClosedToTheScanner(t *testing.T) {
	svc, repo := newLineageStack(t)
	srcPath := t.TempDir()
	source := lineageTestSource(srcPath)

	for _, tc := range []struct {
		name   string
		fp     string
		status model.LineageStatus
	}{
		{"accepted_risk", "fp-accepted", model.LineageStatusAcceptedRisk},
		{"false_positive", "fp-false-positive", model.LineageStatusFalsePositive},
		{"resolved", "fp-resolved", model.LineageStatusResolved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := svc.ProcessAuditFindings(lineageTestAudit("audit-a"), source,
				[]model.Finding{lineageTestFinding(tc.fp)}); err != nil {
				t.Fatalf("seed scan: %v", err)
			}
			l, err := repo.GetLineageByFingerprint(tc.fp, srcPath, "cwe")
			if err != nil || l == nil {
				t.Fatalf("seed lineage: %v", err)
			}
			if err := repo.UpdateStatus(l.ID, string(tc.status), "", ""); err != nil {
				t.Fatalf("set %s: %v", tc.status, err)
			}

			if err := svc.ProcessAuditFindings(lineageTestAudit("audit-b"), source,
				[]model.Finding{lineageTestFinding("fp-unrelated-" + tc.fp)}); err != nil {
				t.Fatalf("clean scan: %v", err)
			}
			if got := statusOf(t, repo, tc.fp, srcPath); got != tc.status {
				t.Fatalf("expected %q to survive a clean scan, got %q", tc.status, got)
			}
		})
	}
}
