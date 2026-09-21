package repository

import (
	"database/sql"
	"fmt"
	"log"
)

// Feature 0091 §7 — THE BRIDGE BETWEEN THE BACKFILLED KEY AND THE RESOLVED ONE.
//
// THE DEFECT IT EXISTS FOR. `target_key` is written by two different authors
// that cannot produce the same string:
//
//   - migration 027 step 4 (and its SQLite mirror in sqlite_target_identity.go)
//     backfills every historical row with pure STRING work over the recorded
//     path, because the directories those rows name are gone: a container
//     mount, a per-ingest clone dir deleted months ago. It yields
//     `path:<project segment>` — `path:blu-simulator`.
//   - service.ResolveTarget (§7.1) resolves a LIVE source by asking git for a
//     remote and stating the disk for a scan-root marker. It yields
//     `git:<remote>` or `marker:<sha1(root)>` — for the same project,
//     `marker:949707e6…`.
//
// Those namespaces are disjoint, so after the migration `ActiveByTarget` with
// the resolved key matches ZERO of the backfilled rows. The failure is silent
// and looks exactly like a clean scan: no row is closed (safe), but no row is
// MATCHED either, so every finding takes the create branch and the human
// triage attached to the old row — accepted_risk, false_positive, notes,
// ticket — is orphaned. That is precisely the outcome §7 exists to prevent,
// re-created by the fix for it.
//
// THE BRIDGE. Reads consult the resolved key AND the key the backfill would
// have produced for the same path, exactly as feature 0079 reads both
// fingerprint_v2 and v1. It CONVERGES: a row matched through the legacy key is
// re-keyed to the resolved one by the very upsert that matched it, so the
// second scan of a target finds it through the primary key and the bridge is
// left carrying only rows nothing has re-sighted yet.
//
// The rule is recomputed from `sources` rather than remembered, so it stays
// the same answer the backfill gave without a column to hold it. The one case
// where it can drift is a path that acquires a DEEPER source row after the
// backfill ran (a later sub-path scan of it); the bridge then misses those few
// rows, which leaves them exactly where they are today — unmatched — and never
// mis-attributes them to another project.

// legacyTargetKeyFor recomputes migration 027's string-only attribution for
// one source path. Shared by both dialects because the rule is pure Go over
// dialect-neutral SQL: `SELECT DISTINCT path FROM sources`.
func legacyTargetKeyFor(db *sql.DB, sourcePath string) (string, error) {
	roots, err := knownScanRoots(db)
	if err != nil {
		return "", fmt.Errorf("legacy target key: %w", err)
	}
	return stringTargetKey(sourcePath, roots), nil
}

// LegacyTargetKey implements LineageRepository for PostgreSQL.
func (r *PostgresLineageRepo) LegacyTargetKey(sourcePath string) (string, error) {
	return legacyTargetKeyFor(r.db, sourcePath)
}

// LegacyTargetKey implements LineageRepository for SQLite.
func (r *SQLiteLineageRepo) LegacyTargetKey(sourcePath string) (string, error) {
	return legacyTargetKeyFor(r.db, sourcePath)
}

// ── THE SAME BRIDGE, FOR THE READ SIDE ────────────────────────────────────
//
// The closure pass consults both keys (activeRows -> legacyKey ->
// ActiveByTarget). The P4 read side did NOT, and that asymmetry is visible on
// the dashboard the moment a source is re-ingested: `stampTargetKey` moves the
// SOURCE to the resolved `git:`/`marker:` key while its finding_lineage rows
// keep the `path:` key the backfill gave them, and they migrate one at a time
// as each finding is re-found. In between, `mergeTargetCounts` surfaces the
// orphaned lineage key as a target of its own, so one project shows as two —
// one with the scan history and no findings, one with the findings and no
// scan history — and NEITHER aggregate is the whole report.
//
// It does not self-heal on its own, either: the pass only ever re-keys rows it
// MATCHES, and terminal rows (`fixed` and the user-decided three) are never in
// the pass, so the `status=all` report and the `fixed` tile would stay split
// for ever. Reading both keys is what makes the split invisible while the
// write side converges what it can.

// targetAliases is the two directions of the same relation, built once per
// read: which legacy keys belong to a resolved target, and which resolved
// target a legacy key belongs to.
type targetAliases struct {
	byTarget map[string][]string
	resolved map[string]string
}

// loadTargetAliases derives the relation from `sources`, which is the only
// place that records both a path and the key the live resolver gave it. For
// every source path it recomputes migration 027's string-only attribution —
// the same call the write-side bridge makes — and pairs it with the key the
// row actually carries.
//
// A source whose two keys already agree contributes nothing: the bridge exists
// only for the rows the backfill and the resolver disagree about.
func loadTargetAliases(db *sql.DB) (targetAliases, error) {
	out := targetAliases{byTarget: map[string][]string{}, resolved: map[string]string{}}
	roots, err := knownScanRoots(db)
	if err != nil {
		return out, fmt.Errorf("target aliases: %w", err)
	}
	rows, err := db.Query(`SELECT DISTINCT COALESCE(target_key,''), path FROM sources
	                        WHERE COALESCE(target_key,'') <> ''`)
	if err != nil {
		return out, fmt.Errorf("target aliases: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key, p string
		if err := rows.Scan(&key, &p); err != nil {
			return out, fmt.Errorf("scan target alias: %w", err)
		}
		legacy := stringTargetKey(p, roots)
		if legacy == "" || legacy == key {
			continue
		}
		if _, taken := out.resolved[legacy]; taken {
			// Two resolved targets claiming one legacy key: the backfill's
			// first-segment rule pooled two projects that the live resolver
			// separates. Attributing the rows to either would be a guess, so
			// the bridge declines and they stay where they are.
			continue
		}
		out.resolved[legacy] = key
		out.byTarget[key] = append(out.byTarget[key], legacy)
	}
	return out, rows.Err()
}

// targetReadKeys is the key list every target-scoped READ scopes to: the key
// asked for, plus its legacy twins. Always non-empty and always primary-first.
//
// Failure degrades to the primary key alone rather than erroring: losing the
// bridge costs rows on a dashboard, and failing the read costs the page.
func targetReadKeys(db *sql.DB, targetKey string) []string {
	if targetKey == "" {
		return nil
	}
	aliases, err := loadTargetAliases(db)
	if err != nil {
		log.Printf("[lineage] target aliases for %s: %v", targetKey, err)
		return []string{targetKey}
	}
	return append([]string{targetKey}, aliases.byTarget[targetKey]...)
}

// TargetReadKeys implements LineageRepository for PostgreSQL.
func (r *PostgresLineageRepo) TargetReadKeys(targetKey string) []string {
	return targetReadKeys(r.db, targetKey)
}

// TargetReadKeys implements LineageRepository for SQLite.
func (r *SQLiteLineageRepo) TargetReadKeys(targetKey string) []string {
	return targetReadKeys(r.db, targetKey)
}
