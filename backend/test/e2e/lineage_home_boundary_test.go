//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

// Target identity must never resolve a project root AT or ABOVE the user's
// home directory when the scan root is strictly below it.
//
// THE DEFECT. A stray package.json (or a dotfiles .git) in the home directory
// made the marker climb run past an unmarked scan root and stop at $HOME. Every
// unmarked, non-git project under the home directory then resolved to the SAME
// key — marker:<sha1(home)> — and shared one lineage history: one project's
// scan could close, regress or match another project's rows. LLM-tier paths
// were stored relative to $HOME ("src/proj/backend/x.go") because the offset
// was "src/proj".
//
// THE CARRY. Rows already written under the home-climbed key hold human triage
// (false_positive, accepted_risk). The next scan of such a source must move the
// rows that are ITS OWN — source_path at or under the scan root — onto the
// corrected key, with their relative paths rebased into the corrected root,
// and must leave every other source's rows under the bad key untouched.

type homeWorld struct {
	t       *testing.T
	svc     service.LineageService
	repo    repository.LineageRepository
	home    string
	proj    string
	other   string
	homeKey string
}

func newHomeWorld(t *testing.T, newRepo func(t *testing.T) repository.LineageRepository) *homeWorld {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home", "someone")
	proj := filepath.Join(home, "src", "proj")
	other := filepath.Join(home, "src", "other")
	for _, d := range []string{filepath.Join(proj, "backend"), other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	// The stray marker in the home directory, and nothing at either root.
	if err := os.WriteFile(filepath.Join(home, "package.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write stray marker: %v", err)
	}
	t.Setenv("HOME", home)
	repo := newRepo(t)
	w := &homeWorld{t: t, svc: service.NewLineageService(repo), repo: repo,
		home: home, proj: proj, other: other}
	// Scanning the home directory itself is unchanged by the boundary, so it
	// yields exactly the key the pre-fix climb gave every project below it.
	w.homeKey = service.ResolveTarget(&model.Source{Type: model.SourceTypeLocal, Path: home}).Key
	return w
}

func homeSQLiteRepo(t *testing.T) repository.LineageRepository {
	t.Helper()
	base, err := repository.NewSQLiteRepo(filepath.Join(t.TempDir(), "home_boundary.db"))
	if err != nil {
		t.Fatalf("open sqlite repo: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })
	return repository.NewSQLiteLineageRepo(base.DB())
}

// seed plants a row the way the pre-fix resolver wrote it: under the
// home-climbed key, with a path relative to the home directory.
func (w *homeWorld) seed(label, sourcePath, filePath string, status model.LineageStatus) *model.FindingLineage {
	w.t.Helper()
	now := time.Now().UTC()
	l := &model.FindingLineage{
		Fingerprint: "fp-" + label, FingerprintV2: "fpv2-" + label,
		SourcePath: sourcePath, AgentType: "cwe", CurrentStatus: status,
		FirstAuditID: "audit-home-0", FirstFoundAt: now,
		LatestAuditID: "audit-home-0", LatestFoundAt: &now,
		Severity: string(model.SeverityHigh), Category: "CWE-502", Title: label,
		FilePath: filePath, TargetKey: w.homeKey, SeenCount: 1,
		Provenance: "llm_l5_verified", QuoteHash: targetQuoteHash,
	}
	if err := w.repo.UpsertLineage(l); err != nil {
		w.t.Fatalf("seed %q: %v", label, err)
	}
	return l
}

// allRowsOf lists a source's rows in every status the fixture uses — the
// default listing returns only active rows, and the carried ones are triaged.
func (w *homeWorld) allRowsOf(sourcePath string) map[string]model.FindingLineage {
	w.t.Helper()
	out := lineageRowsAcross(w.t, w.repo, sourcePath)
	for _, st := range []model.LineageStatus{model.LineageStatusFalsePositive, model.LineageStatusAcceptedRisk} {
		rows, err := w.repo.ListBySourcePath(sourcePath, string(st), 500, 0)
		if err != nil {
			w.t.Fatalf("list %s rows: %v", st, err)
		}
		for _, r := range rows {
			out[r.ID] = r
		}
	}
	return out
}

func TestHomeClimbedLineageIsCarriedToTheCorrectedTarget(t *testing.T) {
	w := newHomeWorld(t, homeSQLiteRepo)
	src := &model.Source{ID: "src-proj", Type: model.SourceTypeLocal, Path: w.proj}

	wantKey := "path:" + filepath.ToSlash(w.proj)
	if got := service.ResolveTarget(src); got.Key != wantKey || got.Offset != "" {
		t.Fatalf("an unmarked scan root below $HOME must resolve to its own path, "+
			"never to the home directory's marker: got key=%q root=%q offset=%q, want %q",
			got.Key, got.Root, got.Offset, wantKey)
	}
	if w.homeKey == wantKey {
		t.Fatalf("fixture: the home key must differ from the corrected key (%q)", wantKey)
	}

	reported := w.seed("reported", w.proj, "src/proj/backend/x.go", model.LineageStatusFalsePositive)
	silent := w.seed("silent", w.proj, "src/proj/backend/y.go", model.LineageStatusAcceptedRisk)
	theirs := w.seed("theirs", w.other, "src/other/z.go", model.LineageStatusFalsePositive)

	// The next scan of the project re-reports one finding, in agent
	// coordinates (relative to the scan root).
	result := evidenceResult(llmTargetFinding("fp-reported", "fpv2-reported", "backend/x.go"))
	if err := w.svc.RecordScanOutcome(lineageTestAudit("audit-home-1"), src, "cwe", result); err != nil {
		t.Fatalf("scan: %v", err)
	}

	rows := w.allRowsOf(w.proj)
	if len(rows) != 2 {
		t.Fatalf("the re-reported finding must match its carried row, not mint a new one: "+
			"got %d rows under the project:%s", len(rows), summarizeRows(rows))
	}
	for _, c := range []struct {
		row    *model.FindingLineage
		status model.LineageStatus
		path   string
	}{
		{reported, model.LineageStatusFalsePositive, "backend/x.go"},
		{silent, model.LineageStatusAcceptedRisk, "backend/y.go"},
	} {
		now := reloadLineage(t, w.repo, c.row.ID)
		if now.TargetKey != wantKey {
			t.Errorf("%s: row must be carried to %q, still under %q", c.row.Title, wantKey, now.TargetKey)
		}
		if now.CurrentStatus != c.status {
			t.Errorf("%s: triage must survive the carry: status %q, want %q", c.row.Title, now.CurrentStatus, c.status)
		}
		if now.FilePath != c.path {
			t.Errorf("%s: path must be rebased into the corrected root: %q, want %q", c.row.Title, now.FilePath, c.path)
		}
	}

	other := reloadLineage(t, w.repo, theirs.ID)
	if other.TargetKey != w.homeKey || other.FilePath != "src/other/z.go" ||
		other.CurrentStatus != model.LineageStatusFalsePositive {
		t.Fatalf("another source's row under the shared bad key must be untouched: "+
			"key=%q path=%q status=%q", other.TargetKey, other.FilePath, other.CurrentStatus)
	}
}

// Scanning the home directory itself keeps today's behaviour and carries
// nothing: the boundary only applies strictly below $HOME.
func TestHomeDirectoryScanKeepsItsKeyAndCarriesNothing(t *testing.T) {
	w := newHomeWorld(t, homeSQLiteRepo)
	theirs := w.seed("theirs", w.other, "src/other/z.go", model.LineageStatusFalsePositive)
	src := &model.Source{ID: "src-home", Type: model.SourceTypeLocal, Path: w.home}
	if err := w.svc.RecordScanOutcome(lineageTestAudit("audit-home-2"), src, "cwe",
		evidenceResult(targetNoise("fp-noise"))); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got := reloadLineage(t, w.repo, theirs.ID); got.TargetKey != w.homeKey || got.FilePath != "src/other/z.go" {
		t.Fatalf("a scan of $HOME itself must not re-key anything: key=%q path=%q", got.TargetKey, got.FilePath)
	}
}
