//go:build e2e

package e2e

import (
	"reflect"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

// Feature 0096 §4.2 through the SERVICE, not the repo: "a CWE-only scan (no
// mapping) leaves the map untouched". The storage test pins the merge rule on
// fresh structs; this one pins that the service never sends the labels it READ
// back as the merge patch. The row it re-sights was fetched at the start of the
// scan, so replaying its labels would be a read-modify-write: a concurrent
// mapping run that relabelled the row in between would be silently reverted to
// the snapshot.

// racingLineageRepo lands a concurrent labelling write on the target row just
// before the service's own update of it — i.e. after the scan's lookup read
// the row, which is the window a real concurrent audit occupies.
type racingLineageRepo struct {
	repository.LineageRepository
	rowID string
	race  func()
	once  sync.Once
}

func (r *racingLineageRepo) UpsertLineage(l *model.FindingLineage) error {
	if l.ID != "" && l.ID == r.rowID {
		r.once.Do(r.race)
	}
	return r.LineageRepository.UpsertLineage(l)
}

func TestCWEOnlySightingDoesNotRevertLabelsWrittenSinceItsRead(t *testing.T) {
	_, repo := newLineageStack(t)
	srcPath := t.TempDir()
	source := lineageTestSource(srcPath)
	const fp = "fp-0096-sighting-race"
	finding := lineageTestFinding(fp)

	// Scan 1 creates the row through the real service; a mapping run then
	// labels it with the 2025 key.
	svc := service.NewLineageService(repo)
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-1"), source, "cwe",
		&model.ScanResult{Findings: []model.Finding{finding}}); err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	row := labelledRowOf(t, repo, fp, srcPath)
	relabel(t, repo, fp, srcPath, map[string][]string{"owasp:2025": {"A07"}})

	// Scan 2 is CWE-only. Between its lookup and its update, a concurrent
	// mapping run replaces the 2025 key.
	moved := map[string][]string{"owasp:2025": {"A07", "A02"}}
	racing := &racingLineageRepo{LineageRepository: repo, rowID: row.ID,
		race: func() { relabel(t, repo, fp, srcPath, moved) }}
	if err := service.NewLineageService(racing).RecordScanOutcome(lineageTestAudit("audit-2"), source, "cwe",
		&model.ScanResult{Findings: []model.Finding{finding}}); err != nil {
		t.Fatalf("scan 2: %v", err)
	}

	got := labelledRowOf(t, repo, fp, srcPath)
	if got.ID != row.ID || got.LatestAuditID != "audit-2" {
		t.Fatalf("scan 2 must re-sight the same row: id %s->%s latest_audit_id=%q",
			row.ID, got.ID, got.LatestAuditID)
	}
	if !reflect.DeepEqual(got.ComplianceLabels, moved) {
		t.Errorf("a CWE-only sighting must leave the labels untouched: got %v, want %v "+
			"(the scan replayed the labels it read as its patch)", got.ComplianceLabels, moved)
	}
}

func labelledRowOf(t *testing.T, repo repository.LineageRepository, fp, sourcePath string) *model.FindingLineage {
	t.Helper()
	l, err := repo.GetLineageByFingerprint(fp, sourcePath, "cwe")
	if err != nil || l == nil {
		t.Fatalf("lineage row %s: %v (row=%v)", fp, err, l)
	}
	return l
}

// relabel writes the row back with only the given labels as its patch — the
// storage-level shape of a mapping run's sighting.
func relabel(t *testing.T, repo repository.LineageRepository, fp, sourcePath string, labels map[string][]string) {
	t.Helper()
	l := labelledRowOf(t, repo, fp, sourcePath)
	l.ComplianceLabels = labels
	if err := repo.UpsertLineage(l); err != nil {
		t.Fatalf("relabel: %v", err)
	}
}
