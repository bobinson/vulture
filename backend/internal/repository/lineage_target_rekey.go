package repository

import (
	"database/sql"
	"fmt"
	"log"
	"path"
	"strings"
	"time"
)

// TargetRekey moves one source's lineage rows from a retired target key to
// the corrected one (the carry from a home-climbed key; see
// service/lineage_home_bridge.go).
type TargetRekey struct {
	// From is the retired key; To the key the live resolver now gives.
	From, To string
	// ScanRoot scopes the move: only rows whose source_path is this directory
	// or below it. The retired key can be shared by several unrelated sources,
	// and their rows are not this scan's to move.
	ScanRoot string
	// Rebase rewrites a row's stored file_path into To's coordinates. Nil
	// keeps the path.
	Rebase func(filePath string) string
}

// applies reports whether the move names two distinct keys and a scope.
func (m TargetRekey) applies() bool {
	return m.From != "" && m.To != "" && m.From != m.To && m.ScanRoot != ""
}

func (m TargetRekey) rebase(p string) string {
	if m.Rebase == nil {
		return p
	}
	return m.Rebase(p)
}

// rekeyCandidate is the slice of a row the move needs.
type rekeyCandidate struct{ id, filePath string }

// rekeyTarget is RekeyTarget for both dialects. Merged losers move with their
// survivors: they sit outside uq_lineage_target, so they cannot collide.
func rekeyTarget(db *sql.DB, pg bool, m TargetRekey) (int, error) {
	if !m.applies() {
		return 0, nil
	}
	rows, err := rekeyCandidates(db, pg, m)
	if err != nil {
		return 0, err
	}
	return rekeyRows(db, pg, m, rows)
}

// rekeyCandidates reads every row under From whose source_path is in scope.
// The scope test runs in Go rather than as a LIKE so a `%` or `_` in a path
// can never widen it.
func rekeyCandidates(db *sql.DB, pg bool, m TargetRekey) ([]rekeyCandidate, error) {
	d := &sqlDialect{pg: pg}
	q := `SELECT ` + d.textCol("id") + `, COALESCE(source_path,''), COALESCE(file_path,'')
	        FROM finding_lineage WHERE target_key = ` + d.ph(m.From)
	rows, err := db.Query(q, d.args...)
	if err != nil {
		return nil, fmt.Errorf("rekey target: read %s: %w", m.From, err)
	}
	defer rows.Close()
	return scanRekeyCandidates(rows, m.ScanRoot)
}

func scanRekeyCandidates(rows *sql.Rows, scanRoot string) ([]rekeyCandidate, error) {
	var out []rekeyCandidate
	for rows.Next() {
		var c rekeyCandidate
		var sourcePath string
		if err := rows.Scan(&c.id, &sourcePath, &c.filePath); err != nil {
			return nil, fmt.Errorf("rekey target: scan: %w", err)
		}
		if underScanRoot(scanRoot, sourcePath) {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

// rekeyRows applies the move row by row. A row whose identity is already live
// under To (the same finding recorded both ways) is left under From and
// logged: merging it would have to pick between two triage decisions, and
// leaving it is exactly today's state.
func rekeyRows(db *sql.DB, pg bool, m TargetRekey, rows []rekeyCandidate) (int, error) {
	moved := 0
	for _, c := range rows {
		ok, err := rekeyRow(db, pg, m, c)
		if err != nil {
			return moved, err
		}
		if ok {
			moved++
		}
	}
	return moved, nil
}

func rekeyRow(db *sql.DB, pg bool, m TargetRekey, c rekeyCandidate) (bool, error) {
	d := &sqlDialect{pg: pg}
	q := `UPDATE finding_lineage SET target_key = ` + d.ph(m.To) +
		`, file_path = ` + d.ph(m.rebase(c.filePath)) + `, updated_at = ` + nowSQL(d) +
		` WHERE id = ` + d.ph(c.id) + ` AND target_key = ` + d.ph(m.From)
	res, err := db.Exec(q, d.args...)
	if isTargetIdentityConflict(err) {
		log.Printf("[lineage] rekey %s: row %s already live under %s; left in place", m.From, c.id, m.To)
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("rekey target: row %s: %w", c.id, err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// nowSQL renders the current time the way each dialect stores updated_at.
func nowSQL(d *sqlDialect) string {
	if d.pg {
		return "now()"
	}
	return d.ph(time.Now().UTC().Format(time.RFC3339))
}

// underScanRoot reports whether p is root or below it, by whole segments.
func underScanRoot(root, p string) bool {
	r, q := cleanSlashPath(root), cleanSlashPath(p)
	return r == q || isPathAncestor(r, q)
}

func cleanSlashPath(p string) string {
	return strings.TrimRight(path.Clean(strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")), "/")
}

// RekeyTarget implements LineageRepository for PostgreSQL.
func (r *PostgresLineageRepo) RekeyTarget(m TargetRekey) (int, error) {
	return rekeyTarget(r.db, true, m)
}

// RekeyTarget implements LineageRepository for SQLite.
func (r *SQLiteLineageRepo) RekeyTarget(m TargetRekey) (int, error) {
	return rekeyTarget(r.db, false, m)
}
