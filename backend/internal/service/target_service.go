package service

import (
	"fmt"
	"path"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// Feature 0091 §10 — the target-scoped read side.
//
// The repository answers in the vocabulary of the database (a target key, a
// root path, a scan path); this layer turns that into the vocabulary of the
// page: a NAME a human recognises, and the SUB-PATH that distinguishes a
// `.vscode` scan from a root scan of the same codebase. Neither derivation
// belongs in SQL — one of them needs the git-remote normaliser that already
// lives in this package — and neither belongs in the handler, which must stay
// a parser of query strings.

// TargetService is the read side of a codebase's history.
type TargetService interface {
	// ListTargets is the dashboard: every codebase this installation has
	// scanned, most recently scanned first.
	ListTargets() ([]model.TargetSummary, error)
	// Scans is one target's history rail, newest first.
	Scans(targetKey string) ([]model.TargetScan, error)
	// Aggregate is the report: unique findings for a target, filtered and
	// paged in SQL.
	Aggregate(q model.AggregateQuery) (*model.AggregateReport, error)
}

type targetService struct {
	repo repository.LineageRepository
}

// NewTargetService creates the target read service over a lineage repository.
func NewTargetService(repo repository.LineageRepository) TargetService {
	return &targetService{repo: repo}
}

func (s *targetService) ListTargets() ([]model.TargetSummary, error) {
	targets, err := s.repo.ListTargets()
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	for i := range targets {
		targets[i].DisplayName = TargetDisplayName(targets[i])
	}
	if targets == nil {
		targets = []model.TargetSummary{}
	}
	return targets, nil
}

func (s *targetService) Scans(targetKey string) ([]model.TargetScan, error) {
	scans, err := s.repo.TargetScans(targetKey)
	if err != nil {
		return nil, fmt.Errorf("target scans: %w", err)
	}
	root := shallowestPath(scans)
	for i := range scans {
		scans[i].SubPath = subPathUnder(root, scans[i].Path)
	}
	if scans == nil {
		scans = []model.TargetScan{}
	}
	return scans, nil
}

// Aggregate runs the report and stamps the selection's scan count onto every
// row.
//
// ScanCount is the DENOMINATOR of "seen in 2 of 5 scans" and belongs to the
// selection, not to the row — which is why it is applied here rather than
// projected per row in SQL, where it would be the same number joined onto
// every row of the page.
func (s *targetService) Aggregate(q model.AggregateQuery) (*model.AggregateReport, error) {
	report, err := s.repo.AggregateByTarget(q)
	if err != nil {
		return nil, fmt.Errorf("aggregate target: %w", err)
	}
	scanCount, err := s.repo.CountTargetScans(q.TargetKey, q.Scans)
	if err != nil {
		return nil, fmt.Errorf("count target scans: %w", err)
	}
	for i := range report.Rows {
		report.Rows[i].ScanCount = scanCount
	}
	if report.Rows == nil {
		report.Rows = []model.AggregateRow{}
	}
	return report, nil
}

// unattributedDisplayName is what an `unresolved:` key is called on the
// dashboard (§10.2). Such a key is a bare container mount — `/mnt/source` with
// no project segment under it — and nothing can be attributed to a codebase
// from that alone, so it is shown once, as itself, and never folded into a
// project.
const unattributedDisplayName = "Unattributed scans"

// TargetDisplayName renders a target key as something a human recognises.
//
// The order is the order of confidence. A git remote names the repository
// wherever it is checked out, so it wins; the recorded root path is next,
// because a marker-resolved or path-resolved target IS its directory; the key
// itself is the last resort, and it is never wrong, only ugly.
//
// The path is deliberately below the remote: a git ingest clones into a fresh
// temporary directory on EVERY run, so the path of a git target names the
// clone, not the codebase.
func TargetDisplayName(t model.TargetSummary) string {
	if strings.HasPrefix(t.TargetKey, targetKindUnresolved) {
		return unattributedDisplayName
	}
	if name := remoteDisplayName(t.TargetKey, t.GitURL); name != "" {
		return name
	}
	if name := lastPathSegment(t.RootPath); name != "" {
		return name
	}
	return t.TargetKey
}

// remoteDisplayName pulls the repository name out of a git-derived identity.
//
// A `git:` key holds one of two things: a normalised remote (`github.com/acme/
// proj`) or a sha1 of a working tree that has a .git directory but no remote.
// The slash is what tells them apart — a digest has none — and only the first
// carries a name.
func remoteDisplayName(key, gitURL string) string {
	remote := strings.TrimPrefix(key, targetKindGit)
	if !strings.HasPrefix(key, targetKindGit) || !strings.Contains(remote, "/") {
		remote = NormalizeGitRemote(gitURL)
	}
	if !strings.Contains(remote, "/") {
		return ""
	}
	return lastPathSegment(remote)
}

// lastPathSegment is the final element of a slash path, "" when there is none.
func lastPathSegment(p string) string {
	p = strings.TrimRight(strings.TrimSpace(p), "/")
	if p == "" || p == "/" {
		return ""
	}
	base := path.Base(p)
	if base == "." || base == "/" {
		return ""
	}
	return base
}

// shallowestPath is the target's root as the recorded scans see it: the
// shortest path among them.
//
// A root scan's path is a PREFIX of every sub-path scan of the same tree, so
// it is also the shortest, and the minimum by length is the root whenever the
// scans are nested. When they are not — two git clones into two temporary
// directories — the answer is one of the clones, and subPathUnder's prefix
// test rejects it, which is the intended outcome: an offset between two
// unrelated directories is not a sub-path.
func shallowestPath(scans []model.TargetScan) string {
	root := ""
	for _, s := range scans {
		p := canonicalScanPath(s.Path)
		if p == "" {
			continue
		}
		if root == "" || len(p) < len(root) {
			root = p
		}
	}
	return root
}

// subPathUnder returns the scan's offset below the target root, "" for a scan
// standing on the root itself or for a path that is not under it at all.
func subPathUnder(root, scanPath string) string {
	root = canonicalScanPath(root)
	p := canonicalScanPath(scanPath)
	if root == "" || p == "" || p == root {
		return ""
	}
	if !strings.HasPrefix(p, root+"/") {
		return ""
	}
	return strings.TrimPrefix(p, root+"/")
}
