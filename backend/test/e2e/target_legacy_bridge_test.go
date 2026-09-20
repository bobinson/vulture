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

// Feature 0091 §7 / §10.1 — THE READ SIDE NEEDS THE SAME BRIDGE THE WRITE SIDE
// HAS.
//
// `target_key` is written by two authors that cannot produce the same string.
// Migration 027 backfills historical rows with pure string work over the
// recorded path (`path:vulture`), because the directories they name are gone.
// `service.ResolveTarget` keys a LIVE source by asking git for a remote and
// stating the disk for a marker (`marker:<sha1>` / `git:<remote>`).
//
// The closure pass already reads both (activeRows -> legacyKey ->
// ActiveByTarget). The P4 read side did not, and the split becomes visible the
// moment a source is re-ingested — which happens on every scan of a local
// path: `stampTargetKey` moves the SOURCE to the resolved key while its
// finding_lineage rows keep the backfilled one. The user then sees TWO
// dashboard entries for one project, one with the scan history and no
// findings, one with the findings and no scan history, and neither aggregate
// is the whole report.
//
// It does not converge on its own either: the pass re-keys only rows it
// MATCHES, and a terminal row (`fixed`, or one a human decided) is never in
// the pass at all — so the `status=all` report and the `fixed` tile would stay
// split for ever.
func TestTargetReadsBridgeTheBackfilledKey(t *testing.T) {
	w := newBridgeWorld(t)

	// The state migration 027 + one re-ingest leaves behind: the SOURCE
	// carries the resolved key, its lineage rows carry the backfilled one.
	if w.resolvedKey == w.legacyKey {
		t.Fatalf("fixture: the two authors must disagree, else there is nothing to bridge (%q)", w.resolvedKey)
	}
	w.seedScan("audit-bridge-1")
	open := w.seedRow("open-row", w.legacyKey, model.LineageStatusOpen, "audit-bridge-1")
	fixed := w.seedRow("fixed-row", w.legacyKey, model.LineageStatusFixed, "audit-bridge-1")

	// ── One codebase is ONE dashboard row ────────────────────────────────
	targets, err := w.lineage.ListTargets()
	if err != nil {
		t.Fatalf("list targets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("one codebase must be one target however its rows are keyed, got %d: %s",
			len(targets), targetKeysOf(targets))
	}
	if targets[0].TargetKey != w.resolvedKey {
		t.Fatalf("the surviving row is the one the live resolver names: got %q, want %q",
			targets[0].TargetKey, w.resolvedKey)
	}
	if targets[0].ActiveCount != 1 || targets[0].FixedCount != 1 {
		t.Fatalf("the backfilled rows are this target's rows: active=%d fixed=%d, want 1/1",
			targets[0].ActiveCount, targets[0].FixedCount)
	}
	if targets[0].ScanCount != 1 {
		t.Fatalf("the scan history belongs to the same target: scan_count=%d, want 1", targets[0].ScanCount)
	}

	// ── The aggregate is the WHOLE report ────────────────────────────────
	all, err := w.lineage.AggregateByTarget(model.AggregateQuery{
		TargetKey: w.resolvedKey, IncludeTerminal: true, Page: 1, PageSize: 50,
	})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	got := map[string]bool{}
	for _, r := range all.Rows {
		got[r.LineageID] = true
	}
	if !got[open.ID] || !got[fixed.ID] {
		t.Fatalf("the report for %q must contain every row of the codebase, including the ones "+
			"still carrying the backfilled key: got %d rows %v, want %s and %s",
			w.resolvedKey, len(all.Rows), got, open.ID, fixed.ID)
	}
	if all.Tiles.Unique != 2 || all.Tiles.Fixed != 1 {
		t.Fatalf("the tiles count the same rows the table lists: unique=%d fixed=%d, want 2/1",
			all.Tiles.Unique, all.Tiles.Fixed)
	}

	// ── And the scan rail / denominator resolve to the same target ───────
	scans, err := w.lineage.TargetScans(w.resolvedKey)
	if err != nil {
		t.Fatalf("target scans: %v", err)
	}
	if len(scans) != 1 {
		t.Fatalf("the target's scan history is one scan, got %d", len(scans))
	}
	n, err := w.lineage.CountTargetScans(w.resolvedKey, nil)
	if err != nil {
		t.Fatalf("count target scans: %v", err)
	}
	if n != 1 {
		t.Fatalf(`the "seen in N of M scans" denominator is the target's scan count: got %d, want 1`, n)
	}
}

// TestTargetBridgeDoesNotPoolUnrelatedCodebases is the control that keeps the
// bridge honest. Over-merging is worse than not merging: it puts one project's
// findings into another project's report. A key that is nobody's legacy twin
// must stay its own target.
func TestTargetBridgeDoesNotPoolUnrelatedCodebases(t *testing.T) {
	w := newBridgeWorld(t)
	w.seedScan("audit-ctrl-1")
	w.seedRow("mine", w.legacyKey, model.LineageStatusOpen, "audit-ctrl-1")
	// A backfilled key for a DIFFERENT project, with no source of its own.
	w.seedRow("theirs", "path:someone-else", model.LineageStatusOpen, "audit-ctrl-1")

	targets, err := w.lineage.ListTargets()
	if err != nil {
		t.Fatalf("list targets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("an unrelated backfilled key is its own target, not this one's: got %d: %s",
			len(targets), targetKeysOf(targets))
	}
	report, err := w.lineage.AggregateByTarget(model.AggregateQuery{
		TargetKey: w.resolvedKey, IncludeTerminal: true, Page: 1, PageSize: 50,
	})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.Total != 1 {
		t.Fatalf("the bridge must not pull another codebase's rows into this report: total=%d, want 1",
			report.Total)
	}
}

// ── harness ──────────────────────────────────────────────────────────────

type bridgeWorld struct {
	t           *testing.T
	base        *repository.SQLiteRepo
	lineage     repository.LineageRepository
	root        string
	resolvedKey string
	legacyKey   string
	seq         int
}

func newBridgeWorld(t *testing.T) *bridgeWorld {
	t.Helper()
	tmp := t.TempDir()
	root := filepath.Join(tmp, "vulture")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir scan root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"vulture"}`), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	base, err := repository.NewSQLiteRepo(filepath.Join(tmp, "bridge.db"))
	if err != nil {
		t.Fatalf("open sqlite repo: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })
	lineage := repository.NewSQLiteLineageRepo(base.DB())

	w := &bridgeWorld{t: t, base: base, lineage: lineage, root: root}
	w.resolvedKey = service.ResolveTarget(&model.Source{Type: model.SourceTypeLocal, Path: root}).Key
	// The source has to exist before the legacy rule has a scan root to work
	// from — `knownScanRoots` reads `sources`, exactly as 027 step 4 does.
	w.seedSource("src-seed")
	legacy, err := lineage.LegacyTargetKey(root)
	if err != nil {
		t.Fatalf("legacy target key: %v", err)
	}
	w.legacyKey = legacy
	return w
}

// seedSource writes a source row carrying the RESOLVED key — what
// stampTargetKey writes on the next ingest of a local path.
func (w *bridgeWorld) seedSource(id string) *model.Source {
	w.t.Helper()
	src := &model.Source{ID: id, Type: model.SourceTypeLocal, Path: w.root,
		TargetKey: w.resolvedKey, CreatedAt: time.Now().UTC()}
	if err := w.base.CreateSource(src); err != nil {
		w.t.Fatalf("create source: %v", err)
	}
	return src
}

func (w *bridgeWorld) seedScan(auditID string) {
	w.t.Helper()
	src := w.seedSource("src-" + auditID)
	audit := &model.Audit{ID: auditID, SourceID: src.ID, Types: []string{"cwe"},
		Status: model.AuditStatusCompleted, CreatedAt: time.Now().UTC()}
	if err := w.base.CreateAudit(audit); err != nil {
		w.t.Fatalf("create audit: %v", err)
	}
}

// seedRow plants a lineage row under an explicit target key — the backfilled
// one, which is the state 027 leaves behind and which nothing re-keys until
// the finding is re-found.
func (w *bridgeWorld) seedRow(label, key string, status model.LineageStatus, auditID string) *model.FindingLineage {
	w.t.Helper()
	w.seq++
	now := time.Now().UTC()
	l := &model.FindingLineage{
		Fingerprint: "fp-" + label, SourcePath: w.root, AgentType: "cwe",
		CurrentStatus: status, FirstAuditID: auditID, FirstFoundAt: now,
		LatestAuditID: auditID, LatestFoundAt: &now,
		Severity: string(model.SeverityHigh), Category: "CWE-78",
		Title: label, FilePath: "src/a.py", TargetKey: key, SeenCount: 1,
	}
	if err := w.lineage.UpsertLineage(l); err != nil {
		w.t.Fatalf("seed lineage %q: %v", label, err)
	}
	return l
}

func targetKeysOf(targets []model.TargetSummary) string {
	out := ""
	for _, t := range targets {
		out += "\n    " + t.TargetKey + "  active=" + itoa(t.ActiveCount) +
			" fixed=" + itoa(t.FixedCount) + " scans=" + itoa(t.ScanCount)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for ; n > 0; n /= 10 {
		digits = string(rune('0'+n%10)) + digits
	}
	return digits
}
