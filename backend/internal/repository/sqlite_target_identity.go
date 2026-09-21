package repository

import (
	"database/sql"
	"fmt"
	"log"
	"path"
	"sort"
	"strings"

	"github.com/vulture/backend/internal/pathutil"
)

// Feature 0091 §7 / migration 027 steps 3-6, for SQLite.
//
// WHY IT IS HERE AND NOT IN THE .sql FILE. The Postgres schema is owned by the
// embedded migration runner; SQLite's is owned by migrate() in sqlite_repo.go
// (a known 0040 follow-up). So a target-identity change that lands only in
// 027 is half a change: every local-dev database keeps NULL target keys, reads
// through ActiveByTarget return nothing, and the closure pass silently stops
// seeing rows it should act on. This file is the other half.
//
// It is a Go mirror rather than a transliteration because SQLite has no
// plpgsql: the Postgres step 4 resolves "the first path segment under a known
// scan root" in a stored function, and the same rule is expressed here in Go.
// Both are pure STRING work over the recorded paths — no git, no filesystem —
// for the same reason: the paths in an old row name directories that no longer
// exist on any machine, and a migration that stats them stalls startup.

// migrateLineageTargetIdentity runs the SQLite half of 027 steps 3-6.
//
// Every step is predicated on work being outstanding, so the whole function is
// a handful of no-op queries on every start after the first.
func migrateLineageTargetIdentity(db *sql.DB) {
	if !targetIdentityWorkPending(db) {
		ensureTargetIdentityIndexes(db)
		return
	}
	// The unique index has to come DOWN first. Attributing the second half of
	// a duplicate pair is precisely the write that violates it, and the merge
	// that would resolve the pair cannot run until both halves are keyed — so
	// leaving the index up makes the backfill fail on exactly the rows it
	// exists to reunite. Postgres does not hit this because 027 builds the
	// index after its own backfill; SQLite's schema is re-applied on every
	// start, so the index is already there.
	if _, err := db.Exec(`DROP INDEX IF EXISTS uq_lineage_target`); err != nil {
		log.Printf("[sqlite] drop uq_lineage_target before backfill: %v", err)
	}
	backfillLineageFingerprintV2(db)
	backfillLineageProvenance(db)
	backfillLineageTargetKey(db)
	mergeDuplicateLineagesByTarget(db)
	ensureTargetIdentityIndexes(db)
}

// targetIdentityWorkPending reports whether anything is left to attribute. It
// is what keeps the backfill from re-scanning the table on every start: after
// one complete run every row is keyed, and the Go writer keys each new one at
// insert.
// The provenance arm is a JOIN rather than a bare "is any provenance empty",
// and it has to be: a row whose fingerprint appears in no finding that records
// a provenance has no answer available, so counting it as outstanding would
// leave the gate true for ever and re-run every backfill on every start. The
// join is what makes the question "is there work LEFT TO DO" instead of "is
// anything still empty". idx_findings_identity is what makes it cheap.
//
// It cannot be folded into the target_key arm either. A database migrated by
// an earlier build — one that keyed target_key but did not yet carry the
// provenance step — is fully keyed and still needs this, and that is exactly
// the upgrade path an operator takes.
func targetIdentityWorkPending(db *sql.DB) bool {
	ensureFindingsIdentityIndex(db)
	var pending int
	err := db.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM finding_lineage WHERE COALESCE(target_key,'') = '')
		    OR EXISTS (SELECT 1 FROM sources WHERE COALESCE(target_key,'') = '')
		    OR EXISTS (SELECT 1 FROM finding_lineage fl
		                WHERE COALESCE(fl.provenance,'') = ''
		                  AND EXISTS (SELECT 1 FROM findings f
		                               WHERE f.fingerprint = fl.fingerprint
		                                 AND f.agent_type  = fl.agent_type
		                                 AND COALESCE(TRIM(f.provenance),'') <> ''))`).Scan(&pending)
	if err != nil {
		log.Printf("[sqlite] check target-identity backfill state: %v", err)
		return false
	}
	return pending > 0
}

// ensureFindingsIdentityIndex covers the (fingerprint, agent_type) pair every
// lineage backfill correlates on. Postgres has had idx_findings_fingerprint
// since 004; SQLite indexed findings only by audit_id and file_path, so each
// of these correlated subqueries was a full scan of `findings` PER LINEAGE
// ROW — 10k x 93k on the reference corpus.
func ensureFindingsIdentityIndex(db *sql.DB) {
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_findings_identity
		ON findings (fingerprint, agent_type)`); err != nil {
		log.Printf("[sqlite] idx_findings_identity: %v", err)
	}
}

// ensureTargetIdentityIndexes builds the two indexes of 027 step 6.
//
// The unique one is what stops the duplicates from coming back: without it the
// next scan under a third path form re-creates what the merge just collapsed.
// A failure is logged rather than swallowed, because it means duplicates
// survived the merge — exactly the thing an operator needs to be told about.
func ensureTargetIdentityIndexes(db *sql.DB) {
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_lineage_active_target
		ON finding_lineage (target_key, agent_type)`); err != nil {
		log.Printf("[sqlite] idx_lineage_active_target: %v", err)
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS uq_lineage_target
		ON finding_lineage (target_key, agent_type, COALESCE(NULLIF(fingerprint_v2,''), fingerprint))
		WHERE merged_into IS NULL`); err != nil {
		log.Printf("[sqlite] uq_lineage_target not created (duplicate lineage rows remain?): %v", err)
	}
}

// backfillLineageFingerprintV2 copies the 0079 identity from `findings`, which
// is where it already lives. It is the matching key from P3 onward; a row that
// never acquires one keeps NULL and continues to match on v1 (the 0079
// bridge).
func backfillLineageFingerprintV2(db *sql.DB) {
	_, err := db.Exec(`
		UPDATE finding_lineage
		   SET fingerprint_v2 = (
		        SELECT MIN(f.fingerprint_v2) FROM findings f
		         WHERE f.fingerprint = finding_lineage.fingerprint
		           AND f.agent_type  = finding_lineage.agent_type
		           AND COALESCE(f.fingerprint_v2,'') <> '')
		 WHERE COALESCE(fingerprint_v2,'') = ''
		   AND EXISTS (
		        SELECT 1 FROM findings f
		         WHERE f.fingerprint = finding_lineage.fingerprint
		           AND f.agent_type  = finding_lineage.agent_type
		           AND COALESCE(f.fingerprint_v2,'') <> '')`)
	if err != nil {
		log.Printf("[sqlite] backfill lineage fingerprint_v2: %v", err)
	}
}

// backfillLineageProvenance copies the tier from `findings`.
//
// WHY THIS IS THE MOST LOAD-BEARING OF THE THREE BACKFILLS. `provenance` is
// the ONLY input to model.TierOf, and TierOf("") answers `det` — the pre-0091
// rule that a finding missing from a scan has been repaired. A row left
// without it therefore closes the first time the model does not mention it,
// which is precisely the incident feature 0091 exists to prevent, and the
// deliberate empty-is-deterministic default (documented on TierOf, pinned by
// its own test) is only defensible for a row whose tier is genuinely unknown.
//
// It cannot be recovered at runtime. The row acquires provenance in
// updateExistingLineage, which runs only when the finding is REPORTED — and
// the row that needs the tier is by construction the one this scan did NOT
// report. So the rows that need it are exactly the rows that can never be
// given it later.
//
// AN LLM PROVENANCE WINS A TIE. One fingerprint can be reported by both tiers.
// Taking the deterministic one would let the row close on the model's
// silence; taking the LLM one costs at most an `unconfirmed` the next scan
// resolves. Only one of those two errors can destroy triage state, so the
// choice is not a preference. (A plain MIN() would pick `catalog_rollup` over
// `llm_l5_verified` and get this exactly backwards.)
func backfillLineageProvenance(db *sql.DB) {
	_, err := db.Exec(`
		UPDATE finding_lineage
		   SET provenance = COALESCE(
		        (SELECT MIN(TRIM(f.provenance)) FROM findings f
		          WHERE f.fingerprint = finding_lineage.fingerprint
		            AND f.agent_type  = finding_lineage.agent_type
		            AND LOWER(TRIM(COALESCE(f.provenance,''))) LIKE 'llm%'),
		        (SELECT MIN(TRIM(f.provenance)) FROM findings f
		          WHERE f.fingerprint = finding_lineage.fingerprint
		            AND f.agent_type  = finding_lineage.agent_type
		            AND COALESCE(TRIM(f.provenance),'') <> ''))
		 WHERE COALESCE(provenance,'') = ''
		   AND EXISTS (
		        SELECT 1 FROM findings f
		         WHERE f.fingerprint = finding_lineage.fingerprint
		           AND f.agent_type  = finding_lineage.agent_type
		           AND COALESCE(TRIM(f.provenance),'') <> '')`)
	if err != nil {
		log.Printf("[sqlite] backfill lineage provenance: %v", err)
	}
}

// backfillLineageTargetKey attributes every row that has no target key yet.
// The predicate is what makes it both resumable and idempotent.
func backfillLineageTargetKey(db *sql.DB) {
	roots, err := knownScanRoots(db)
	if err != nil {
		log.Printf("[sqlite] read known scan roots: %v", err)
		return
	}
	// finding_lineage first: `sources` is where the roots come from, so keying
	// it cannot change the answer for the rows that matter.
	keyRows(db, roots, "finding_lineage", "source_path")
	keyRows(db, roots, "sources", "path")
}

// keyRows attributes every row of one table that has no target key yet. The
// predicate is what makes the backfill both resumable and idempotent.
func keyRows(db *sql.DB, roots []string, table, pathColumn string) {
	pending, err := unkeyedPaths(db, table, pathColumn)
	if err != nil {
		log.Printf("[sqlite] read unkeyed %s rows: %v", table, err)
		return
	}
	for id, p := range pending {
		if _, err := db.Exec(
			`UPDATE `+table+` SET target_key = ? WHERE id = ?`, stringTargetKey(p, roots), id); err != nil {
			log.Printf("[sqlite] set %s.target_key id=%s: %v", table, id, err)
		}
	}
}

// unkeyedPaths returns id -> path for every row of a table with no target key.
func unkeyedPaths(db *sql.DB, table, pathColumn string) (map[string]string, error) {
	rows, err := db.Query(
		`SELECT id, ` + pathColumn + ` FROM ` + table + ` WHERE COALESCE(target_key,'') = ''`)
	if err != nil {
		return nil, fmt.Errorf("query unkeyed %s: %w", table, err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, p string
		if err := rows.Scan(&id, &p); err != nil {
			return nil, fmt.Errorf("scan unkeyed %s: %w", table, err)
		}
		out[id] = p
	}
	return out, rows.Err()
}

// knownScanRoots returns the directories that have held a scanned project on
// this installation, longest first. `sources` is the only record of that, and
// without it "the first segment under a root" has no root to be under.
func knownScanRoots(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT DISTINCT path FROM sources`)
	if err != nil {
		return nil, fmt.Errorf("query sources: %w", err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	isSource := map[string]bool{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("scan source path: %w", err)
		}
		norm := normalizedScanPath(p)
		seen[parentOfNormalized(norm)] = true
		isSource[norm] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sources: %w", err)
	}
	// A candidate container that is ITSELF a scanned source path is dropped, so a
	// sub-path scan inherits its project rather than becoming its own target
	// (LLD 7.2). Scanning `<proj>/.vscode` otherwise makes `<proj>` a container
	// and keys the row to `path:.vscode`.
	//
	// "/" is exempt and must stay: it is what a bare `/mnt/source` normalises to,
	// and dropping it stops `/mnt/source/<proj>` unifying with the native path.
	out := make([]string, 0, len(seen))
	for r := range seen {
		if r != "/" && isSource[r] {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out, nil
}

// stringTargetKey is the SQLite twin of the Postgres vlt_0091_target_key():
// strip the run-mode prefix, then take the FIRST path segment under a known
// scan root.
//
// `unresolved:` for a path that names no project. Nothing can be attributed to
// a codebase from `/mnt/source` alone, and guessing is how one project's
// history acquires another project's findings.
func stringTargetKey(sourcePath string, roots []string) string {
	norm := normalizedScanPath(sourcePath)
	if norm == "/" {
		return "unresolved:" + trimTrailingSlash(sourcePath)
	}
	for _, root := range roots {
		rest, ok := segmentUnder(norm, root)
		if !ok {
			continue
		}
		return "path:" + rest
	}
	return "path:" + norm
}

// segmentUnder returns the first path segment of norm below root.
func segmentUnder(norm, root string) (string, bool) {
	rest := ""
	switch {
	case root == "/":
		rest = strings.TrimPrefix(norm, "/")
	case strings.HasPrefix(norm, root+"/"):
		rest = strings.TrimPrefix(norm, root+"/")
	default:
		return "", false
	}
	seg := strings.SplitN(rest, "/", 2)[0]
	return seg, seg != ""
}

// normalizedScanPath is the run-mode-stripped, always-absolute form every
// comparison here is made in. "/" means "the bare mount": nothing left.
func normalizedScanPath(p string) string {
	stripped, matched := pathutil.StripRunModePrefix(p)
	if stripped == "" {
		return "/"
	}
	if matched && !strings.HasPrefix(stripped, "/") {
		return "/" + stripped
	}
	return trimTrailingSlash(stripped)
}

func trimTrailingSlash(p string) string {
	p = strings.TrimRight(strings.TrimSpace(p), "/")
	if p == "" {
		return "/"
	}
	return p
}

// parentOfNormalized is path.Dir with "/" for a top-level entry.
func parentOfNormalized(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	return path.Dir(p)
}

// lineageMergeRow is one candidate for the duplicate merge.
type lineageMergeRow struct {
	id        string
	group     string
	firstSeen string
	refNumber int
}

// mergeDuplicateLineagesByTarget is 027 step 5 for SQLite: the same finding
// recorded twice because the tree was scanned under two path forms collapses
// to one row.
//
// Survivorship is not a matter of taste, and the rules are the Postgres ones:
// the EARLIEST first_found_at survives (or a merge silently resets how long
// every finding has been open), the LOWEST ref_number is carried (that is the
// one already quoted in tickets and commits), the loser is MARKED rather than
// deleted so a stale link still resolves, and the loser's EVENTS move to the
// survivor because they are the audit trail.
func mergeDuplicateLineagesByTarget(db *sql.DB) {
	groups, err := duplicateLineageGroups(db)
	if err != nil {
		log.Printf("[sqlite] scan for duplicate lineages: %v", err)
		return
	}
	for _, rows := range groups {
		if err := mergeOneLineageGroup(db, rows); err != nil {
			log.Printf("[sqlite] merge duplicate lineage group %q: %v", rows[0].group, err)
		}
	}
}

// duplicateLineageGroups returns only the groups that actually hold more than
// one row, so the common case costs one indexed scan and no writes.
func duplicateLineageGroups(db *sql.DB) (map[string][]lineageMergeRow, error) {
	rows, err := db.Query(`
		SELECT id,
		       target_key || char(31) || agent_type || char(31) || COALESCE(NULLIF(fingerprint_v2,''), fingerprint),
		       COALESCE(first_found_at,''), COALESCE(ref_number, 0)
		  FROM finding_lineage
		 WHERE merged_into IS NULL AND COALESCE(target_key,'') <> ''`)
	if err != nil {
		return nil, fmt.Errorf("query lineage groups: %w", err)
	}
	defer rows.Close()
	byGroup := map[string][]lineageMergeRow{}
	for rows.Next() {
		var r lineageMergeRow
		if err := rows.Scan(&r.id, &r.group, &r.firstSeen, &r.refNumber); err != nil {
			return nil, fmt.Errorf("scan lineage group row: %w", err)
		}
		byGroup[r.group] = append(byGroup[r.group], r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate lineage groups: %w", err)
	}
	for key, rs := range byGroup {
		if len(rs) < 2 {
			delete(byGroup, key)
		}
	}
	return byGroup, nil
}

// mergeOneLineageGroup folds every row of one group into its survivor.
func mergeOneLineageGroup(db *sql.DB, rows []lineageMergeRow) error {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].firstSeen != rows[j].firstSeen {
			return rows[i].firstSeen < rows[j].firstSeen
		}
		return rows[i].id < rows[j].id
	})
	survivor := rows[0]
	if err := carryLowestRef(db, survivor, lowestRef(rows)); err != nil {
		return err
	}
	for _, loser := range rows[1:] {
		if err := foldLineageLoser(db, survivor.id, loser.id); err != nil {
			return err
		}
	}
	return nil
}

// lowestRef is the smallest positive ref_number in the group — the one that
// has been quoted longest, and therefore the one that must keep resolving.
func lowestRef(rows []lineageMergeRow) int {
	best := 0
	for _, r := range rows {
		if r.refNumber > 0 && (best == 0 || r.refNumber < best) {
			best = r.refNumber
		}
	}
	return best
}

func carryLowestRef(db *sql.DB, survivor lineageMergeRow, minRef int) error {
	if minRef == 0 || minRef == survivor.refNumber {
		return nil
	}
	if _, err := db.Exec(`UPDATE finding_lineage SET ref_number = ? WHERE id = ?`,
		minRef, survivor.id); err != nil {
		return fmt.Errorf("carry ref_number: %w", err)
	}
	return nil
}

// foldLineageLoser moves one loser's timeline onto the survivor, records the
// merge, and marks the loser.
func foldLineageLoser(db *sql.DB, survivorID, loserID string) error {
	if _, err := db.Exec(`UPDATE lineage_events SET lineage_id = ? WHERE lineage_id = ?`,
		survivorID, loserID); err != nil {
		return fmt.Errorf("move events: %w", err)
	}
	if _, err := db.Exec(`
		INSERT INTO lineage_events (id, lineage_id, event_type, notes, created_at)
		VALUES (?, ?, 'merged', ?, datetime('now'))`,
		generateLineageUUID(), survivorID,
		"absorbed duplicate lineage "+loserID+" (027 target-identity merge)"); err != nil {
		return fmt.Errorf("record merge event: %w", err)
	}
	if _, err := db.Exec(`UPDATE finding_lineage SET merged_into = ? WHERE id = ?`,
		survivorID, loserID); err != nil {
		return fmt.Errorf("mark loser merged: %w", err)
	}
	return nil
}
