//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

// Feature 0091 — THE SEAMS BETWEEN P2 AND P3, where each half is green on its
// own tests and the pair is wrong.
//
// Every other 0091 test exercises one mechanism. These three exercise a
// mechanism against ANOTHER mechanism's output, because that is where this
// feature's failures actually live and because each of the three below was a
// live defect measured in this tree, not a hypothetical:
//
//	1. TestPrunedDirIsOutOfScopeAcrossMounts
//	   P2 reports `pruned_dirs` root-relative; P3 hands the closure pass rows
//	   recorded under OTHER mounts of the same target, whose file_path is
//	   absolute and in the other mount's coordinates. The prefix comparison
//	   could not match, the row was judged in scope, and the deterministic rule
//	   CLOSED it — 0091's own reference incident, re-created by 0091.
//
//	2. TestReSightingReAnchorsFilePathSoRepairStillCloses
//	   The guard for (1) must not become a freeze. A row whose path can never
//	   be placed is out_of_scope on every scan and a genuine repair can never
//	   close it. This pins the other direction.
//
//	3. TestBackfilledTargetKeyIsReachableFromTheResolvedKey
//	   Migration 027 keys historical rows by pure string work (`path:<segment>`)
//	   because the directories they name are gone; the live resolver keys by git
//	   remote or on-disk marker (`git:…` / `marker:…`). Disjoint namespaces: the
//	   first scan after the migration matches NONE of the 10,663 backfilled rows
//	   and re-records every finding under a new VLT ref, orphaning the triage a
//	   human attached. Nothing else notices, because no closure happens either.
//
// All three are written against the REAL SQLite stack — the same migrate() path
// a local install runs, including the 027 mirror in sqlite_target_identity.go —
// so a fix that only lands in the .sql file cannot pass them.

// seamRemote is one repository reached through two mounts. Identity comes from
// the remote (§7.1 step 1), which is what makes the two scans one target and
// therefore what puts the old mount's rows in the new scan's pass at all.
const seamRemote = "https://github.com/acme/seam.git"

func seamSource(id, path string) *model.Source {
	return &model.Source{
		ID: id, Type: model.SourceTypeGit, URL: seamRemote, Path: path,
		GitRemoteURL: seamRemote, GitBranch: "main", GitCommitShort: "abc1234",
	}
}

// seamFinding is deterministic on purpose. The deterministic tier is the one
// that closes on absence, so it is the only tier in which a broken scope check
// destroys data rather than merely mislabelling it.
func seamFinding(v1, v2, filePath string) model.Finding {
	return model.Finding{
		AgentType: "cwe", Severity: model.SeverityCritical, Category: "CWE-506",
		Title: "Task runs a shell command on folder open", FilePath: filePath,
		LineStart: 7, LineEnd: 7, Fingerprint: v1, FingerprintV2: v2, Provenance: "skill",
	}
}

// seamOnlyRowID returns the single lineage row under path, failing loudly when
// there is not exactly one.
func seamOnlyRowID(t *testing.T, repo repository.LineageRepository, path string) string {
	t.Helper()
	rows := lineageRowsAcross(t, repo, path)
	if len(rows) != 1 {
		t.Fatalf("expected exactly one seeded lineage row under %q, got %d:%s",
			path, len(rows), summarizeRows(rows))
	}
	for id := range rows {
		return id
	}
	return ""
}

// TestPrunedDirIsOutOfScopeAcrossMounts is TestPrunedDirIsOutOfScopeNotFixed's
// missing case: the same contract, but with the row and the scan in DIFFERENT
// mounts of one target — which is the configuration target identity newly
// creates and the only one in which the comparison has no common coordinate
// system to fall back on.
func TestPrunedDirIsOutOfScopeAcrossMounts(t *testing.T) {
	svc, repo := newLineageStack(t)

	// Scan 1, docker: the row is written with an absolute file_path in the
	// container's coordinates, which is what agents emit and what 8,254 of the
	// 10,663 live rows carry.
	docker := seamSource("src-docker", "/mnt/source/proj")
	vscodePath := "/mnt/source/proj/.vscode/tasks.json"
	if err := svc.RecordScanOutcome(lineageTestAudit("seam-1"), docker, "cwe",
		evidenceResult(seamFinding("fp-v1-docker", "fpv2-autorun", vscodePath))); err != nil {
		t.Fatalf("docker scan: %v", err)
	}
	id := seamOnlyRowID(t, repo, "/mnt/source/proj")

	// Scan 2, native, same target, and the walker refused to enter .vscode.
	native := seamSource("src-native", "/home/x/proj")
	pruned := &model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
		PrunedDirs:   []string{".idea", ".vscode"},
		Findings:     []model.Finding{targetNoise("fp-seam-noise")},
	}
	if err := svc.RecordScanOutcome(lineageTestAudit("seam-2"), native, "cwe", pruned); err != nil {
		t.Fatalf("native scan: %v", err)
	}

	after := reloadLineage(t, repo, id)
	if after.CurrentStatus == model.LineageStatusFixed {
		t.Fatalf("a scan that never entered .vscode closed the finding inside it. The row's "+
			"file_path %q is in the mount the FIRST scan used; the scan reporting pruned_dirs %v "+
			"stood at %q. A scope check that cannot place the row's path must answer \"unknown\", "+
			"and unknown never closes.",
			after.FilePath, pruned.PrunedDirs, native.Path)
	}
	if after.CurrentStatus != model.LineageStatusOpen {
		t.Fatalf("an out-of-scope row is left exactly as it was: want %q, got %q",
			model.LineageStatusOpen, after.CurrentStatus)
	}
	if !hasEvent(t, repo, id, model.LineageEventOutOfScope) {
		t.Fatalf("the scan must RECORD that it could not have seen the path, got events %v",
			eventTypesOf(t, repo, id))
	}
}

// TestReSightingReAnchorsFilePathSoRepairStillCloses is the control for the
// test above: refusing to close what cannot be placed is only correct if a row
// can get back to placeable coordinates. It does so the moment a scan re-finds
// the finding, because that scan just read the file and its path is current.
//
// Without this, the guard above trades a false `fixed` for a permanent `open`:
// the row's file_path is frozen at creation by both upserts, so after one mount
// change it is unplaceable forever and a genuinely repaired finding never
// closes again.
func TestReSightingReAnchorsFilePathSoRepairStillCloses(t *testing.T) {
	svc, repo := newLineageStack(t)

	docker := seamSource("src-docker", "/mnt/source/proj")
	if err := svc.RecordScanOutcome(lineageTestAudit("seam-3"), docker, "cwe",
		evidenceResult(seamFinding("fp-v1-d", "fpv2-x", "/mnt/source/proj/src/build.py"))); err != nil {
		t.Fatalf("docker scan: %v", err)
	}
	id := seamOnlyRowID(t, repo, "/mnt/source/proj")

	// Native scan, code unchanged: re-reported under a NEW v1 (v1 embeds the
	// absolute path) and the same v2.
	native := seamSource("src-native", "/home/x/proj")
	if err := svc.RecordScanOutcome(lineageTestAudit("seam-4"), native, "cwe",
		evidenceResult(seamFinding("fp-v1-n", "fpv2-x", "/home/x/proj/src/build.py"))); err != nil {
		t.Fatalf("native scan: %v", err)
	}
	if got := reloadLineage(t, repo, id).FilePath; got != "/home/x/proj/src/build.py" {
		t.Fatalf("a scan that re-found the finding must leave the row's file_path in ITS "+
			"coordinates, or the scope check can never place the row again: got %q", got)
	}

	// Native scan, the developer removed the offending code.
	if err := svc.RecordScanOutcome(lineageTestAudit("seam-5"), native, "cwe",
		evidenceResult(targetNoise("fp-seam-noise"))); err != nil {
		t.Fatalf("repair scan: %v", err)
	}
	after := reloadLineage(t, repo, id)
	if after.CurrentStatus != model.LineageStatusFixed {
		t.Fatalf("a deterministic finding absent from an in-scope scan is FIXED — the guard "+
			"against closing unplaceable rows must not freeze rows that are placeable again: "+
			"status %q at file_path %q", after.CurrentStatus, after.FilePath)
	}
}

// TestBackfilledTargetKeyIsReachableFromTheResolvedKey is the migration seam.
//
// It stands up a genuinely pre-0091 database — rows inserted with a NULL
// target_key — and lets the real migrate() attribute them, so the key under
// test is the one the shipped backfill writes rather than one the test chose.
// Then it runs an ordinary scan and asserts the historical row is MATCHED:
// same id, same VLT ref, same human notes, and re-keyed to the resolved key so
// the bridge is not needed twice.
func TestBackfilledTargetKeyIsReachableFromTheResolvedKey(t *testing.T) {
	dir := t.TempDir()
	proj := filepath.Join(dir, "src", "blu-simulator")
	mustMkdirAll(t, filepath.Join(proj, "src"))
	mustWrite(t, filepath.Join(proj, "package.json"), "{}") // §7.1 step 2 marker
	appJS := filepath.Join(proj, "src", "app.js")
	mustWrite(t, appJS, "console.log(1)\n")
	dbPath := filepath.Join(dir, "vulture.db")

	seedPre0091Row(t, dbPath, proj, appJS)

	// Reopen: migrate() runs 027's SQLite mirror, which backfills target_key.
	base, err := repository.NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("reopen repo: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })

	var backfilled string
	if err := base.DB().QueryRow(
		`SELECT COALESCE(target_key,'') FROM finding_lineage WHERE id='seam-l1'`).Scan(&backfilled); err != nil {
		t.Fatalf("read backfilled target_key: %v", err)
	}
	if backfilled == "" {
		t.Fatal("the backfill must attribute every row; this one has no target_key at all")
	}

	src := &model.Source{ID: "seam-s1", Type: model.SourceTypeLocal, Path: proj}
	resolved := service.ResolveTarget(src).Key
	lineageRepo := repository.NewSQLiteLineageRepo(base.DB())

	// The defect, measured in place rather than asserted from memory: the
	// resolved key alone reaches NONE of the backfilled rows. This stays in the
	// test so the gap between the two namespaces is visible in its output
	// instead of only in the commit that closed it.
	primaryOnly, err := lineageRepo.GetLineageByFingerprintsForTarget([]string{"fp-historic"}, resolved)
	if err != nil {
		t.Fatalf("primary-key lookup: %v", err)
	}
	t.Logf("backfilled key %q vs resolved key %q — a lookup under the resolved key alone matches %d rows",
		backfilled, resolved, len(primaryOnly))

	svc := service.NewLineageService(lineageRepo)

	if err := svc.RecordScanOutcome(lineageTestAudit("seam-6"), src, "cwe",
		evidenceResult(seamFinding("fp-historic", "", appJS))); err != nil {
		t.Fatalf("rescan: %v", err)
	}

	rows, err := lineageRepo.ListBySourcePath(proj, "", 100, 0)
	if err != nil {
		t.Fatalf("list lineage: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("the historical row (backfilled %q) was not matched by a scan resolving %q, so "+
			"the finding was recorded AGAIN: %d rows. The backfill cannot produce the resolved "+
			"key — it runs without git or a filesystem — so the reads must consult both, or every "+
			"pre-0091 row loses its VLT ref, its first-seen date and its triage on the first scan "+
			"after the migration.", backfilled, resolved, len(rows))
	}
	got := rows[0]
	if got.ID != "seam-l1" {
		t.Fatalf("the surviving row must be the historical one, not a replacement: id %q", got.ID)
	}
	if got.RefNumber != 42 || got.Notes != "accepted by the platform team" {
		t.Fatalf("matching through the bridge must preserve the ref and the human triage: "+
			"ref=%d notes=%q", got.RefNumber, got.Notes)
	}
	if got.TargetKey != resolved {
		t.Fatalf("a row matched through the legacy key must be RE-KEYED to the resolved one, or "+
			"the bridge never empties: target_key %q, resolved %q", got.TargetKey, resolved)
	}
}

// seedPre0091Row writes a source and a lineage row the way an installation
// that predates 0091 holds them: no target_key on either, so the reopen below
// exercises the real backfill rather than a value the test picked.
func seedPre0091Row(t *testing.T, dbPath, projPath, filePath string) {
	t.Helper()
	base, err := repository.NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer func() { _ = base.Close() }()
	if _, err := base.DB().Exec(
		`INSERT INTO sources (id,type,url,path,file_count,created_at)
		 VALUES ('seam-s1','local','',?,1,'2026-01-01T00:00:00Z')`, projPath); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	if _, err := base.DB().Exec(
		`INSERT INTO finding_lineage
		   (id,fingerprint,source_path,agent_type,current_status,notes,
		    first_audit_id,first_found_at,created_at,updated_at,ref_number,
		    severity,category,title,file_path,provenance)
		 VALUES ('seam-l1','fp-historic',?,'cwe','open','accepted by the platform team',
		         'audit-old','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',42,
		         'critical','CWE-506','Task runs a shell command on folder open',?,'skill')`,
		projPath, filePath); err != nil {
		t.Fatalf("seed lineage: %v", err)
	}
}

func mustMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// hasEvent reports whether the row's timeline carries an event of this type.
func hasEvent(t *testing.T, repo repository.LineageRepository, lineageID string, want model.LineageEventType) bool {
	t.Helper()
	for _, e := range eventTypesOf(t, repo, lineageID) {
		if e == want {
			return true
		}
	}
	return false
}
