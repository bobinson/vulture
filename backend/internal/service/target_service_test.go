package service

import (
	"errors"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// Feature 0091 P4 — the two derivations this layer owns (the display name and
// the sub-path) and the one number it stamps (the scan-count denominator).
// The endpoints themselves are pinned by the E2E contract suite.

func TestTargetDisplayName(t *testing.T) {
	for _, tc := range []struct {
		name    string
		summary model.TargetSummary
		want    string
	}{
		{
			// The path of a git target names the CLONE — a fresh temporary
			// directory on every ingest — so the remote has to win.
			"git key beats the clone directory",
			model.TargetSummary{TargetKey: "git:github.com/acme/proj", RootPath: "/tmp/vulture-sources/9f2c1b"},
			"proj",
		},
		{
			"remote from the source url when the key is a digest",
			model.TargetSummary{TargetKey: "git:9f2c1b7d", GitURL: "git@github.com:acme/other.git"},
			"other",
		},
		{
			"marker target is its directory",
			model.TargetSummary{TargetKey: "marker:3cfd0163", RootPath: "/home/user/src/blu-simulator"},
			"blu-simulator",
		},
		{
			"sub-path scans still name the root",
			model.TargetSummary{TargetKey: "path:/repos/vulture", RootPath: "/repos/vulture"},
			"vulture",
		},
		{
			// Nothing can be attributed to a codebase from a bare mount, and
			// guessing is how one project's history acquires another's.
			"unattributed mount",
			model.TargetSummary{TargetKey: "unresolved:/mnt/source", RootPath: "/mnt/source"},
			unattributedDisplayName,
		},
		{
			"nothing to go on falls back to the key",
			model.TargetSummary{TargetKey: "marker:deadbeef"},
			"marker:deadbeef",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := TargetDisplayName(tc.summary); got != tc.want {
				t.Fatalf("TargetDisplayName(%+v) = %q, want %q", tc.summary, got, tc.want)
			}
		})
	}
}

func TestSubPathUnder(t *testing.T) {
	for _, tc := range []struct {
		root, scan, want string
	}{
		{"/repos/blu", "/repos/blu", ""},
		{"/repos/blu", "/repos/blu/.vscode", ".vscode"},
		{"/repos/blu", "/repos/blu/src/api", "src/api"},
		{"/repos/blu/", "/repos/blu/.vscode/", ".vscode"},
		// Not under the root at all: two git clones in two temporary
		// directories are not an offset of one another.
		{"/tmp/clone-a", "/tmp/clone-b", ""},
		// A sibling whose name merely starts the same must not be read as a
		// sub-path of it.
		{"/repos/blu", "/repos/blu-simulator", ""},
		{"", "/repos/blu", ""},
	} {
		if got := subPathUnder(tc.root, tc.scan); got != tc.want {
			t.Errorf("subPathUnder(%q, %q) = %q, want %q", tc.root, tc.scan, got, tc.want)
		}
	}
}

func TestScansDeriveSubPathFromTheShallowestScan(t *testing.T) {
	repo := &repository.MockLineageRepository{
		TargetScansFn: func(string) ([]model.TargetScan, error) {
			return []model.TargetScan{
				{AuditID: "a3", Path: "/repos/blu"},
				{AuditID: "a2", Path: "/repos/blu/.vscode"},
				{AuditID: "a1", Path: "/repos/blu"},
			}, nil
		},
	}
	scans, err := NewTargetService(repo).Scans("marker:blu")
	if err != nil {
		t.Fatalf("Scans: %v", err)
	}
	want := map[string]string{"a1": "", "a2": ".vscode", "a3": ""}
	for _, s := range scans {
		if s.SubPath != want[s.AuditID] {
			t.Errorf("%s sub_path = %q, want %q — a sub-path scan inherits its root's target key, "+
				"so the offset is the only thing distinguishing it in the rail", s.AuditID, s.SubPath, want[s.AuditID])
		}
	}
}

func TestAggregateStampsTheSelectionScanCount(t *testing.T) {
	repo := &repository.MockLineageRepository{
		AggregateByTargetFn: func(q model.AggregateQuery) (*model.AggregateReport, error) {
			return &model.AggregateReport{
				Total: 2, Page: q.Page, PageSize: q.PageSize,
				Rows: []model.AggregateRow{{LineageID: "l1", SeenCount: 3}, {LineageID: "l2", SeenCount: 1}},
			}, nil
		},
		CountTargetScansFn: func(string, []string) (int, error) { return 5, nil },
	}
	report, err := NewTargetService(repo).Aggregate(model.AggregateQuery{TargetKey: "k", Page: 1, PageSize: 50})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	for _, row := range report.Rows {
		if row.ScanCount != 5 {
			t.Fatalf("%s scan_count = %d, want 5 — scan_count is the DENOMINATOR of "+
				"\"seen in N of M scans\" and belongs to the selection, not to the row",
				row.LineageID, row.ScanCount)
		}
	}
	if report.Rows[0].SeenCount != 3 || report.Rows[1].SeenCount != 1 {
		t.Fatalf("seen_count must survive untouched: %+v", report.Rows)
	}
}

func TestAggregateWrapsRepositoryFailures(t *testing.T) {
	boom := errors.New("boom")
	repo := &repository.MockLineageRepository{
		AggregateByTargetFn: func(model.AggregateQuery) (*model.AggregateReport, error) { return nil, boom },
	}
	if _, err := NewTargetService(repo).Aggregate(model.AggregateQuery{TargetKey: "k", Page: 1, PageSize: 50}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the repository error wrapped (%%w), not swallowed", err)
	}
}

func TestListTargetsIsNeverNil(t *testing.T) {
	// The dashboard maps over the response; a null there is a crash, and an
	// installation with no scans yet is the very first thing a new user sees.
	targets, err := NewTargetService(&repository.MockLineageRepository{}).ListTargets()
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if targets == nil {
		t.Fatal("ListTargets returned nil; an empty installation must answer []")
	}
}
