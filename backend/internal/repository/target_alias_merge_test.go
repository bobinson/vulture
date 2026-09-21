package repository

import (
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 §7 / §10.1 — ONE CODEBASE IS ONE DASHBOARD ROW, INCLUDING ITS
// SCANS.
//
// `target_key` has two authors that cannot agree. Migration 027 backfills
// historical rows by string work over the recorded path (`path:blu-simulator`).
// `service.ResolveTarget` keys a live source from its git remote or an on-disk
// marker (`marker:<sha1>`). `loadTargetAliases` bridges the two.
//
// The bridge was applied to the LINEAGE COUNTS only. The scan-derived targets —
// one per distinct `sources.target_key` — were passed through untouched, so a
// codebase with two source rows mid-convergence (the root still carrying the
// backfilled key, a sub-path already re-ingested onto the resolved one) still
// produced TWO dashboard entries: one holding the scan history with no
// findings, one holding the findings with no scan history. That is the exact
// split the bridge exists to hide, measured live on blu-simulator: 3 scans /
// 0 findings under `path:blu-simulator` beside 40 findings under `marker:…`.
func TestMergeTargetCountsFoldsAliasedScanTargets(t *testing.T) {
	t1 := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)

	const legacy = "path:blu-simulator"
	const resolved = "marker:cfd43c7a"

	// Two source rows for one codebase: the root still on the backfilled key
	// with the older scans, the sub-path already re-ingested onto the resolved
	// key with the newer one.
	targets := []model.TargetSummary{
		{TargetKey: legacy, RootPath: "/home/user/danger/blu-simulator", ScanCount: 3, LastScanAt: t2, LastAuditID: "audit-root"},
		{TargetKey: resolved, RootPath: "/home/user/danger/blu-simulator/.vscode", ScanCount: 2, LastScanAt: t1, LastAuditID: "audit-vscode"},
	}
	// Every finding still carries the backfilled key — the pass re-keys only
	// rows it matches, and terminal rows are never in the pass at all.
	counts := map[string]model.TargetSummary{
		legacy: {TargetKey: legacy, ActiveCount: 35, FixedCount: 5},
	}
	aliases := map[string]string{legacy: resolved}

	got := mergeTargetCounts(targets, counts, aliases)

	if len(got) != 1 {
		keys := make([]string, len(got))
		for i, g := range got {
			keys[i] = g.TargetKey
		}
		t.Fatalf("one codebase must be one target however its rows are keyed, got %d: %v", len(got), keys)
	}
	g := got[0]
	if g.TargetKey != resolved {
		t.Errorf("the surviving row is the one the live resolver names: got %q, want %q", g.TargetKey, resolved)
	}
	// Every scan of the codebase, under either key.
	if g.ScanCount != 5 {
		t.Errorf("scan history must survive the fold: got %d, want 5", g.ScanCount)
	}
	if g.ActiveCount != 35 || g.FixedCount != 5 {
		t.Errorf("findings must survive the fold: got active=%d fixed=%d, want 35/5", g.ActiveCount, g.FixedCount)
	}
	// The most recent scan is the most recent under EITHER key — here the
	// root's, which is the one the alias folds away.
	if !g.LastScanAt.Equal(t2) {
		t.Errorf("last scan is the latest across both keys: got %s, want %s", g.LastScanAt, t2)
	}
	if g.LastAuditID != "audit-root" {
		t.Errorf("last audit must be the one at the latest scan: got %q, want %q", g.LastAuditID, "audit-root")
	}
	// The codebase is named after its ROOT, not after whichever sub-path
	// happened to be re-ingested onto the resolved key first. Without this the
	// dashboard called the project ".vscode".
	if want := "/home/user/danger/blu-simulator"; g.RootPath != want {
		t.Errorf("root must be the ancestor, not the scanned sub-path: got %q, want %q", g.RootPath, want)
	}
	// service.TargetDisplayName derives the name from RootPath, so the
	// ancestor above is what makes the dashboard say "blu-simulator" rather
	// than ".vscode". Asserted there rather than here: importing service from
	// a repository test would be an import cycle.
}

// The fold must not depend on which source the query happened to return
// first. Ordering is by last_scan_at, so a sub-path scanned most recently puts
// the descendant row first — and that is exactly the blu-simulator case.
func TestMergeTargetCountsFoldIsOrderIndependent(t *testing.T) {
	t1 := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	const legacy = "path:blu-simulator"
	const resolved = "marker:cfd43c7a"

	// Descendant FIRST, and it is also the most recent scan.
	targets := []model.TargetSummary{
		{TargetKey: resolved, RootPath: "/home/user/danger/blu-simulator/.vscode", ScanCount: 2, LastScanAt: t2, LastAuditID: "audit-vscode"},
		{TargetKey: legacy, RootPath: "/home/user/danger/blu-simulator", ScanCount: 3, LastScanAt: t1, LastAuditID: "audit-root"},
	}
	counts := map[string]model.TargetSummary{
		legacy: {TargetKey: legacy, ActiveCount: 35, FixedCount: 5},
	}
	got := mergeTargetCounts(targets, counts, map[string]string{legacy: resolved})
	if len(got) != 1 {
		t.Fatalf("one codebase must be one target, got %d", len(got))
	}
	g := got[0]
	if want := "/home/user/danger/blu-simulator"; g.RootPath != want {
		t.Errorf("the ancestor is the root whichever row comes first: got %q, want %q", g.RootPath, want)
	}
	if g.ScanCount != 5 || g.ActiveCount != 35 || g.FixedCount != 5 {
		t.Errorf("counts must fold regardless of order: scans=%d active=%d fixed=%d", g.ScanCount, g.ActiveCount, g.FixedCount)
	}
	// The latest scan here belongs to the descendant row.
	if !g.LastScanAt.Equal(t2) || g.LastAuditID != "audit-vscode" {
		t.Errorf("latest scan/audit must travel together: got %s / %q", g.LastScanAt, g.LastAuditID)
	}
}

// A codebase whose keys already agree must be untouched — the bridge exists
// only for the disagreement, and must not merge two genuinely distinct targets.
func TestMergeTargetCountsLeavesUnaliasedTargetsAlone(t *testing.T) {
	t1 := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	targets := []model.TargetSummary{
		{TargetKey: "path:alpha", DisplayName: "alpha", ScanCount: 1, LastScanAt: t1},
		{TargetKey: "path:beta", DisplayName: "beta", ScanCount: 1, LastScanAt: t1},
	}
	counts := map[string]model.TargetSummary{
		"path:alpha": {TargetKey: "path:alpha", ActiveCount: 2},
		"path:beta":  {TargetKey: "path:beta", ActiveCount: 3},
	}
	got := mergeTargetCounts(targets, counts, map[string]string{})
	if len(got) != 2 {
		t.Fatalf("distinct codebases must stay distinct, got %d", len(got))
	}
}
