package repository

import (
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Feature 0096 §6.3 / migration 031, for SQLite: retire the OWASP lineage rows.
//
// The rule is migrations/031_retire_owasp_lineage.sql's, and that file carries
// the reasoning: a live OWASP row folds into its twin — a live row of any other
// agent in the same target (equal key, or the two halves of the 0091 legacy-key
// bridge), the same file (same path relative to the target's shortest scanned
// root, else to the row's own source_path, or the same absolute path), same
// title once the `[A07] ` prefix is removed; cwe first, then the copy's own
// key, then lowest ref — or, with no twin, is retired by merging into itself.
// A triaged OWASP row that disagrees with its twin aborts the whole step; one
// retired with no twin is named in the log; the OWASP row's notes and ticket
// ride on the twin's `absorbed` event.
//
// WHY A MARKER AND NOT THE CANDIDATE PREDICATE. Postgres runs 031 once because
// the runner records it. SQLite's migrate() re-runs on every open, and gating
// on "live OWASP rows exist" would re-retire, on every restart, the rows a
// legacy-mode OWASP agent writes AFTER the upgrade (version skew, a rollback) —
// silently taking live findings out of every read. So the step runs only while
// its name is absent from `data_migrations`, and records it in the same
// transaction as the fold.
//
// Go rather than SQL because SQLite ships no regexp function.

const owaspRetirementMigration = "0096_retire_owasp_lineage"

var owaspTitlePrefix = regexp.MustCompile(`^\[A\d+\] `)

// retireCandidate is one lineage row as the retirement reads it.
type retireCandidate struct {
	id, agent, status, sourcePath, filePath, title, notes, ticket string
	targetKey                                                     sql.NullString
	ref                                                           sql.NullInt64
}

// owaspFold is the decision for one OWASP row: its winning twin (nil = retire)
// and how many twins competed.
type owaspFold struct {
	owasp     retireCandidate
	twin      *retireCandidate
	twinCount int
}

// retireScope is what the rule reads besides the lineage rows: the legacy-key
// bridge, and every scanned root of each (bridged) target, shortest first —
// 031's vlt_0096_alias and vlt_0096_root.
type retireScope struct {
	aliases map[string]string
	roots   map[string][]string
}

// migrateRetireOwaspLineage runs the one-shot retirement. An error aborts
// migrate(), like a failing 031 aborts a Postgres start.
func migrateRetireOwaspLineage(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS data_migrations (
		name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("create data_migrations: %w", err)
	}
	// The marker first: a store that has run the step reads nothing else, so
	// a start never depends on the scope read below (or pays for it).
	if done, err := owaspRetirementApplied(db); err != nil || done {
		return err
	}
	// A row with no target key has no twin, so running while attribution is
	// outstanding would retire it as "no twin" — past the triage-abort check a
	// keyed twin would trigger, and for good, because the marker stops the
	// retry. Defer without the marker; the next start retries.
	if pending, err := retireKeyingPending(db); err != nil || pending {
		if pending {
			log.Printf("[migrate] 0096 owasp lineage: deferred, target-identity attribution still pending")
		}
		return err
	}
	// Read before the transaction: the scope is derived from `sources`, which
	// the fold does not write.
	scope, err := loadRetireScope(db)
	if err != nil {
		return fmt.Errorf("owasp retirement: %w", err)
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin owasp retirement: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	folds, err := retireOwaspLineageOnce(tx, scope)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit owasp retirement: %w", err)
	}
	logOwaspRetirement(folds)
	return nil
}

// retireOwaspLineageOnce is the body of the transaction: nothing when the
// marker is present, otherwise plan, check, fold, and record the marker.
func retireOwaspLineageOnce(tx *sql.Tx, scope retireScope) ([]owaspFold, error) {
	var applied int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM data_migrations WHERE name = ?`,
		owaspRetirementMigration).Scan(&applied); err != nil || applied > 0 {
		return nil, err
	}
	folds, err := planOwaspRetirement(tx, scope)
	if err != nil {
		return nil, err
	}
	if err := refuseTriageDisagreement(folds); err != nil {
		return nil, err
	}
	if err := applyOwaspRetirement(tx, folds); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO data_migrations (name, applied_at) VALUES (?, ?)`,
		owaspRetirementMigration, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return nil, fmt.Errorf("record %s: %w", owaspRetirementMigration, err)
	}
	return folds, nil
}

// owaspRetirementApplied reports whether the one-shot marker is recorded.
func owaspRetirementApplied(db *sql.DB) (bool, error) {
	var applied int
	if err := db.QueryRow(`SELECT COUNT(*) FROM data_migrations WHERE name = ?`,
		owaspRetirementMigration).Scan(&applied); err != nil {
		return false, fmt.Errorf("read %s marker: %w", owaspRetirementMigration, err)
	}
	return applied > 0, nil
}

// retireKeyingPending reports whether any input the twin rule matches on is
// still unattributed: a live lineage row, or a source (its key files the
// target's scanned roots), with no target key. migrateLineageTargetIdentity
// keys every such row on a healthy start, so this is true only when that
// backfill did not complete. The provenance arm of targetIdentityWorkPending
// is deliberately absent: the retirement does not read provenance.
func retireKeyingPending(db *sql.DB) (bool, error) {
	var pending int
	if err := db.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM finding_lineage
		                WHERE merged_into IS NULL AND COALESCE(target_key,'') = '')
		    OR EXISTS (SELECT 1 FROM sources WHERE COALESCE(target_key,'') = '')`).Scan(&pending); err != nil {
		return false, fmt.Errorf("owasp retirement: check target-identity state: %w", err)
	}
	return pending > 0, nil
}

func loadRetireScope(db *sql.DB) (retireScope, error) {
	aliases, err := unambiguousTargetAliases(db)
	if err != nil {
		return retireScope{}, err
	}
	roots, err := targetRoots(db, aliases)
	return retireScope{aliases: aliases, roots: roots}, err
}

// targetRoots files each source's path under its bridged key: its resolved
// key, else the legacy key 027 gave its path.
func targetRoots(db *sql.DB, aliases map[string]string) (map[string][]string, error) {
	scanRoots, err := knownScanRoots(db)
	if err != nil {
		return nil, fmt.Errorf("target roots: %w", err)
	}
	sources, err := sourcePathKeys(db)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, src := range sources {
		key := src.key
		if key == "" {
			key = stringTargetKey(src.path, scanRoots)
		}
		if root := strings.TrimRight(src.path, "/"); root != "" {
			target := bridgedTarget(aliases, key)
			out[target] = append(out[target], root)
		}
	}
	for _, roots := range out {
		sort.Slice(roots, func(i, j int) bool { return shorterPath(roots[i], roots[j]) })
	}
	return out, nil
}

// sourceKey is one `sources` row: its path and its resolved key ("" if none).
type sourceKey struct{ path, key string }

func sourcePathKeys(db *sql.DB) ([]sourceKey, error) {
	rows, err := db.Query(`SELECT DISTINCT path, COALESCE(target_key, '') FROM sources`)
	if err != nil {
		return nil, fmt.Errorf("target roots: %w", err)
	}
	defer rows.Close()
	var out []sourceKey
	for rows.Next() {
		var k sourceKey
		if err := rows.Scan(&k.path, &k.key); err != nil {
			return nil, fmt.Errorf("scan target root: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// shorterPath orders roots shortest first, then lexically for determinism.
func shorterPath(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

const retireColumns = `id, agent_type, current_status, source_path, file_path, title,
	COALESCE(notes, ''), COALESCE(ticket_url, ''), target_key, ref_number`

// planOwaspRetirement pairs every live OWASP row with its winning twin. The
// pool is not narrowed by target_key in SQL: a twin across the bridge carries
// the OTHER key, so the match is made on the bridged target in Go.
func planOwaspRetirement(tx *sql.Tx, scope retireScope) ([]owaspFold, error) {
	owasp, err := queryRetireRows(tx, `SELECT `+retireColumns+` FROM finding_lineage
		WHERE agent_type = 'owasp' AND merged_into IS NULL`)
	if err != nil || len(owasp) == 0 {
		return nil, err
	}
	pool, err := queryRetireRows(tx, `SELECT `+retireColumns+` FROM finding_lineage
		WHERE agent_type <> 'owasp' AND merged_into IS NULL AND target_key IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	return planFolds(owasp, pool, scope), nil
}

// planFolds is the decision itself, over rows already read.
func planFolds(owasp, pool []retireCandidate, scope retireScope) []owaspFold {
	byKey := map[string][]retireCandidate{}
	for _, c := range pool {
		for _, k := range scope.twinKeys(c, c.title) {
			byKey[k] = append(byKey[k], c)
		}
	}
	folds := make([]owaspFold, 0, len(owasp))
	for _, o := range owasp {
		folds = append(folds, foldFor(o, byKey, scope))
	}
	return folds
}

// bridgedTarget is the target a key names: the resolved key a legacy key is an
// alias of, else the key itself — 031's COALESCE(alias.resolved, target_key).
func bridgedTarget(aliases map[string]string, key string) string {
	if resolved, ok := aliases[key]; ok {
		return resolved
	}
	return key
}

// foldFor picks the winner among o's twins. A row with no target key has no
// twin, as in Postgres, where NULL = NULL is not true.
//
// The bucket is shared by every OWASP row with the same bridged target, and the
// ranking depends on the row's OWN key, so it is scanned, never sorted in place,
// and the winner is held as a copy — 031's per-candidate row_number().
func foldFor(o retireCandidate, byKey map[string][]retireCandidate, scope retireScope) owaspFold {
	if !o.targetKey.Valid {
		return owaspFold{owasp: o}
	}
	twins := uniqueTwins(byKey, scope.twinKeys(o, owaspTitlePrefix.ReplaceAllString(o.title, "")))
	if len(twins) == 0 {
		return owaspFold{owasp: o}
	}
	best := twins[0]
	for _, c := range twins[1:] {
		if twinBefore(o.targetKey.String, c, best) {
			best = c
		}
	}
	return owaspFold{owasp: o, twin: &best, twinCount: len(twins)}
}

// twinBefore orders twins: cwe first, then one under the OWASP row's own key
// (not across the bridge), then the lowest ref (NULL last), then id.
func twinBefore(ownKey string, a, b retireCandidate) bool {
	if (a.agent == "cwe") != (b.agent == "cwe") {
		return a.agent == "cwe"
	}
	if aOwn, bOwn := a.targetKey.String == ownKey, b.targetKey.String == ownKey; aOwn != bOwn {
		return aOwn
	}
	if a.ref.Valid != b.ref.Valid {
		return a.ref.Valid
	}
	if a.ref.Int64 != b.ref.Int64 {
		return a.ref.Int64 < b.ref.Int64
	}
	return a.id < b.id
}

// uniqueTwins is the rows found under any of keys, each once — a twin matching
// on both its relative and its absolute path is one twin (031 joins on an OR).
func uniqueTwins(byKey map[string][]retireCandidate, keys []string) []retireCandidate {
	if len(keys) == 1 {
		return byKey[keys[0]]
	}
	seen := map[string]bool{}
	var out []retireCandidate
	for _, k := range keys {
		for _, c := range byKey[k] {
			if !seen[c.id] {
				seen[c.id] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// twinKeys are the keys a row is found under: its path relative to its
// target, and its absolute path when it has one — 031's
// `c.rel = cand.rel OR c.abs = cand.abs`.
func (s retireScope) twinKeys(c retireCandidate, title string) []string {
	target := bridgedTarget(s.aliases, c.targetKey.String)
	abs := absToSource(c.sourcePath, c.filePath)
	keys := []string{"rel\x1f" + target + "\x1f" + s.relToTarget(target, c.sourcePath, abs) + "\x1f" + title}
	if strings.HasPrefix(abs, "/") {
		keys = append(keys, "abs\x1f"+target+"\x1f"+abs+"\x1f"+title)
	}
	return keys
}

// relToTarget is 031's vlt_0096_rel: abs relative to the shortest root of
// target that contains it, else to the row's own source_path.
func (s retireScope) relToTarget(target, sourcePath, abs string) string {
	for _, root := range s.roots[target] {
		if strings.HasPrefix(abs, root+"/") {
			return relToSource(root, abs)
		}
	}
	return relToSource(sourcePath, abs)
}

// absToSource is 031's vlt_0096_abs: a relative file_path resolved against the
// row's own source_path.
func absToSource(sourcePath, filePath string) string {
	root := strings.TrimRight(sourcePath, "/")
	if strings.HasPrefix(filePath, "/") || root == "" {
		return filePath
	}
	return root + "/" + strings.TrimPrefix(filePath, "./")
}

// relToSource is 031's vlt_0096_strip: file_path with "<source_path>/"
// stripped when it is a prefix, then a leading "./".
func relToSource(sourcePath, filePath string) string {
	root := strings.TrimRight(sourcePath, "/")
	if sourcePath != "" && strings.HasPrefix(filePath, root+"/") {
		filePath = filePath[len(root)+1:]
	}
	return strings.TrimPrefix(filePath, "./")
}

func queryRetireRows(tx *sql.Tx, query string) ([]retireCandidate, error) {
	rows, err := tx.Query(query)
	if err != nil {
		return nil, fmt.Errorf("read lineage for owasp retirement: %w", err)
	}
	defer rows.Close()
	var out []retireCandidate
	for rows.Next() {
		var c retireCandidate
		if err := rows.Scan(&c.id, &c.agent, &c.status, &c.sourcePath, &c.filePath, &c.title,
			&c.notes, &c.ticket, &c.targetKey, &c.ref); err != nil {
			return nil, fmt.Errorf("scan lineage for owasp retirement: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// refuseTriageDisagreement is 031's safety stop: a human decision recorded
// only on the OWASP row would be hidden by the fold, because the twin keeps its
// own status.
//
// The rows are named by ref (NULL last) then id, so the message does not
// depend on the order the store returned them in. (031's Postgres message
// aggregates without an ORDER BY; its row order is unspecified.)
func refuseTriageDisagreement(folds []owaspFold) error {
	var disagree []owaspFold
	for _, f := range folds {
		if f.twin != nil && isTriagedStatus(f.owasp.status) && f.twin.status != f.owasp.status {
			disagree = append(disagree, f)
		}
	}
	if len(disagree) == 0 {
		return nil
	}
	sort.Slice(disagree, func(i, j int) bool { return refBefore(disagree[i].owasp, disagree[j].owasp) })
	bad := make([]string, 0, len(disagree))
	for _, f := range disagree {
		bad = append(bad, fmt.Sprintf("%s %s vs twin %s %s",
			retireRef(f.owasp), f.owasp.status, retireRef(*f.twin), f.twin.status))
	}
	return fmt.Errorf("0096: %d triaged OWASP lineage row(s) disagree with the twin they would fold "+
		"into (%s); set the twin's status to match, then restart", len(bad), strings.Join(bad, "; "))
}

func isTriagedStatus(s string) bool {
	return s == "false_positive" || s == "accepted_risk" || s == "resolved"
}

// retireRef renders a ref as FormatRef does, falling back to the id.
func retireRef(c retireCandidate) string {
	if c.ref.Int64 > 0 {
		return fmt.Sprintf("VLT-%04d", c.ref.Int64)
	}
	return c.id
}

// refBefore orders rows by ref, NULL last, then by id.
func refBefore(a, b retireCandidate) bool {
	if a.ref != b.ref {
		return a.ref.Valid && (!b.ref.Valid || a.ref.Int64 < b.ref.Int64)
	}
	return a.id < b.id
}

// retireEvent is one `merged` event the retirement writes.
type retireEvent struct{ on, note string }

// foldOutcome is where the OWASP row points afterwards and what is recorded:
// both sides of a fold, or the retirement alone.
func foldOutcome(f owaspFold) (string, []retireEvent) {
	if f.twin == nil {
		return f.owasp.id, []retireEvent{{f.owasp.id, "0096: OWASP lineage retired, no twin"}}
	}
	return f.twin.id, []retireEvent{
		{f.owasp.id, "0096: OWASP lineage folded into " + retireRef(*f.twin)},
		{f.twin.id, "0096: absorbed OWASP lineage " + retireRef(f.owasp) + absorbedRationale(f.owasp)},
	}
}

// absorbedRationale carries the OWASP row's own notes and ticket onto the
// twin's timeline — ` (false_positive; notes: …; ticket: …)` — or nothing when
// it has neither. The twin row is not rewritten (D4), and the folded row drops
// out of every list, so without this the reason behind a triage is reachable
// only by id.
func absorbedRationale(o retireCandidate) string {
	if o.notes == "" && o.ticket == "" {
		return ""
	}
	parts := []string{o.status}
	if o.notes != "" {
		parts = append(parts, "notes: "+o.notes)
	}
	if o.ticket != "" {
		parts = append(parts, "ticket: "+o.ticket)
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

// applyOwaspRetirement writes the events and the merge pointer. The twin row
// itself is never updated: its status, notes and ticket are the human record.
func applyOwaspRetirement(tx *sql.Tx, folds []owaspFold) error {
	now := time.Now().UTC()
	for _, f := range folds {
		into, events := foldOutcome(f)
		for _, e := range events {
			if _, err := tx.Exec(`INSERT INTO lineage_events (id, lineage_id, event_type, notes, created_at)
				VALUES (?, ?, 'merged', ?, ?)`,
				generateLineageUUID(), e.on, e.note, now.Format(sqliteEventTimeLayout)); err != nil {
				return fmt.Errorf("record 0096 event on %s: %w", e.on, err)
			}
		}
		if _, err := tx.Exec(`UPDATE finding_lineage SET merged_into = ?, updated_at = ? WHERE id = ?`,
			into, now.Format(time.RFC3339), f.owasp.id); err != nil {
			return fmt.Errorf("retire owasp lineage %s: %w", f.owasp.id, err)
		}
	}
	return nil
}

// logOwaspRetirement prints the §10 line, as 031's NOTICE does; silent when
// there was nothing to retire.
func logOwaspRetirement(folds []owaspFold) {
	if len(folds) == 0 {
		return
	}
	twinned, multi := 0, 0
	for _, f := range folds {
		if f.twin != nil {
			twinned++
		}
		if f.twinCount > 1 {
			multi++
		}
	}
	log.Printf("[migrate] 0096 owasp lineage: candidates=%d twinned=%d retired=%d multi_twin=%d",
		len(folds), twinned, len(folds)-twinned, multi)
	if tri := triagedOrphans(folds); len(tri) > 0 {
		log.Printf("[migrate] 0096 owasp lineage: %d triaged row(s) retired with no twin: %s",
			len(tri), strings.Join(tri, "; "))
	}
}

// triagedOrphans names the triaged rows retired with no twin, by ref (NULL
// last) then id, as 031's NOTICE does. There is no twin to disagree with, so
// they do not abort, but their decision is readable only by id from then on.
func triagedOrphans(folds []owaspFold) []string {
	var rows []retireCandidate
	for _, f := range folds {
		if f.twin == nil && isTriagedStatus(f.owasp.status) {
			rows = append(rows, f.owasp)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return refBefore(rows[i], rows[j]) })
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, retireRef(r)+" "+r.status)
	}
	return out
}
