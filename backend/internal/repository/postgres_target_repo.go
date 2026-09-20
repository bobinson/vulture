package repository

import (
	"database/sql"
	"fmt"

	"github.com/lib/pq"
	"github.com/vulture/backend/internal/model"
)

// Feature 0091 §10.1, Postgres half — the production store.
//
// The queries mirror sqlite_target_repo.go statement for statement; what
// differs is only what has to: `$n` placeholders, the `::text` casts the UUID
// columns need, and `types` arriving as a TEXT[] rather than a JSON string.
// Every predicate comes from target_repo.go so the two dialects cannot answer
// the same filter differently.

// ListTargets returns every codebase this installation has scanned.
//
// One statement for the scan side: the window functions collapse "how many
// scans", "which was the newest" and "what is the shallowest path recorded"
// into a single pass, where the obvious shape — a GROUP BY plus a per-target
// lookup of the latest audit — is a query per target.
func (r *PostgresLineageRepo) ListTargets() ([]model.TargetSummary, error) {
	rows, err := r.db.Query(`
		SELECT target_key, audit_id, created_at, root_path, git_url, scan_count
		  FROM (
		    SELECT COALESCE(s.target_key,'')                                        AS target_key,
		           a.id::text                                                       AS audit_id,
		           a.created_at                                                     AS created_at,
		           COALESCE(s.url,'')                                               AS git_url,
		           MIN(s.path)   OVER (PARTITION BY COALESCE(s.target_key,''))      AS root_path,
		           COUNT(*)      OVER (PARTITION BY COALESCE(s.target_key,''))      AS scan_count,
		           ROW_NUMBER()  OVER (PARTITION BY COALESCE(s.target_key,'')
		                                   ORDER BY a.created_at DESC, a.id DESC)   AS rn
		      FROM audits a JOIN sources s ON a.source_id = s.id
		     WHERE COALESCE(s.target_key,'') <> ''
		  ) t
		 WHERE rn = 1`)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	defer rows.Close()
	out, err := scanPGTargetSummaries(rows)
	if err != nil {
		return nil, err
	}
	counts, err := r.targetCounts()
	if err != nil {
		return nil, err
	}
	aliases, err := loadTargetAliases(r.db)
	if err != nil {
		return nil, err
	}
	return mergeTargetCounts(out, counts, aliases.resolved), nil
}

// targetCounts is the lineage half of the target list: one grouped pass over
// finding_lineage instead of three counts per target.
func (r *PostgresLineageRepo) targetCounts() (map[string]model.TargetSummary, error) {
	d := &sqlDialect{pg: true}
	active := activeStatusList(d)
	unconfirmed := d.ph(string(model.LineageStatusUnconfirmed))
	fixed := d.ph(string(model.LineageStatusFixed))
	rows, err := r.db.Query(`
		SELECT COALESCE(target_key,''),
		       COALESCE(SUM(CASE WHEN current_status IN `+active+` THEN 1 ELSE 0 END),0),
		       COALESCE(SUM(CASE WHEN current_status = `+unconfirmed+` THEN 1 ELSE 0 END),0),
		       COALESCE(SUM(CASE WHEN current_status = `+fixed+` THEN 1 ELSE 0 END),0)
		  FROM finding_lineage
		 WHERE COALESCE(target_key,'') <> ''`+notMerged+`
		 GROUP BY COALESCE(target_key,'')`, d.args...)
	if err != nil {
		return nil, fmt.Errorf("target lineage counts: %w", err)
	}
	defer rows.Close()
	return scanTargetCounts(rows)
}

// TargetScans returns the target's scan history, newest first.
func (r *PostgresLineageRepo) TargetScans(targetKey string) ([]model.TargetScan, error) {
	keys := r.TargetReadKeys(targetKey)
	if len(keys) == 0 {
		return nil, nil
	}
	d := &sqlDialect{pg: true}
	in := d.inList(keys)
	rows, err := r.db.Query(`
		SELECT a.id::text, a.created_at, COALESCE(s.path,''), COALESCE(s.git_branch,''), a.types
		  FROM audits a JOIN sources s ON a.source_id = s.id
		 WHERE COALESCE(s.target_key,'') IN `+in+`
		 ORDER BY a.created_at DESC, a.id DESC`, d.args...)
	if err != nil {
		return nil, fmt.Errorf("target scans: %w", err)
	}
	defer rows.Close()
	out, err := scanPGTargetScans(rows)
	if err != nil {
		return nil, err
	}
	return r.attachTierCounts(keys, out)
}

// attachTierCounts fills the det/llm split for every scan in ONE query — see
// the SQLite twin for why a per-scan lookup is not an option.
func (r *PostgresLineageRepo) attachTierCounts(keys []string, scans []model.TargetScan) ([]model.TargetScan, error) {
	if len(scans) == 0 {
		return scans, nil
	}
	d := &sqlDialect{pg: true}
	rows, err := r.db.Query(tierCountQuery(d, keys), d.args...)
	if err != nil {
		return nil, fmt.Errorf("scan tier counts: %w", err)
	}
	defer rows.Close()
	counts, err := scanTierCounts(rows)
	if err != nil {
		return nil, err
	}
	return applyTierCounts(scans, counts), nil
}

// AggregateByTarget answers GET /api/targets/{key}/aggregate from
// `finding_lineage` alone, through idx_lineage_active_target.
//
// Four statements, none of them per row: the tiles (one aggregate pass), the
// filtered COUNT that `total` comes from, the page itself, and one lookup of
// the last event for the ids ON THE PAGE.
func (r *PostgresLineageRepo) AggregateByTarget(q model.AggregateQuery) (*model.AggregateReport, error) {
	report := &model.AggregateReport{Page: q.Page, PageSize: q.PageSize, Rows: []model.AggregateRow{}}
	keys := r.TargetReadKeys(q.TargetKey)
	if len(keys) == 0 {
		return report, nil
	}
	if err := r.readAggregateTiles(keys, q, report); err != nil {
		return nil, err
	}
	if err := r.readAggregateTotal(keys, q, report); err != nil {
		return nil, err
	}
	if err := r.readAggregatePage(keys, q, report); err != nil {
		return nil, err
	}
	return report, r.attachLastEvents(report)
}

func (r *PostgresLineageRepo) readAggregateTiles(keys []string, q model.AggregateQuery, report *model.AggregateReport) error {
	d := &sqlDialect{pg: true}
	cols := tilesSelectSQL(d)
	where := targetScopeSQL(d, keys, q)
	t := &report.Tiles
	err := r.db.QueryRow(`SELECT `+cols+` FROM finding_lineage WHERE `+where, d.args...).
		Scan(&t.Unique, &t.Active, &t.Unconfirmed, &t.Fixed, &t.Critical)
	if err != nil {
		return fmt.Errorf("aggregate tiles: %w", err)
	}
	return nil
}

func (r *PostgresLineageRepo) readAggregateTotal(keys []string, q model.AggregateQuery, report *model.AggregateReport) error {
	d := &sqlDialect{pg: true}
	where := reportFilterSQL(d, keys, q)
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM finding_lineage WHERE `+where, d.args...).
		Scan(&report.Total); err != nil {
		return fmt.Errorf("aggregate total: %w", err)
	}
	return nil
}

func (r *PostgresLineageRepo) readAggregatePage(keys []string, q model.AggregateQuery, report *model.AggregateReport) error {
	d := &sqlDialect{pg: true}
	where := reportFilterSQL(d, keys, q)
	limit := d.ph(q.PageSize)
	offset := d.ph(q.Offset())
	rows, err := r.db.Query(`SELECT `+aggregateRowCols+` FROM finding_lineage WHERE `+where+
		aggregateOrderSQL+` LIMIT `+limit+` OFFSET `+offset, d.args...)
	if err != nil {
		return fmt.Errorf("aggregate page: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s aggregateRowScan
		if err := rows.Scan(&s.id, &s.refNumber, &s.severity, &s.category, &s.title, &s.filePath, &s.sourcePath,
			&s.lineStart, &s.provenance, &s.seenCount, &s.status, &s.firstFoundAt, &s.latestFoundAt); err != nil {
			return fmt.Errorf("scan aggregate row: %w", err)
		}
		report.Rows = append(report.Rows, newAggregateRow(s))
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("aggregate page: %w", err)
	}
	return nil
}

// attachLastEvents resolves the most recent event for the rows ON THE PAGE, in
// one statement bounded by the page's ids.
func (r *PostgresLineageRepo) attachLastEvents(report *model.AggregateReport) error {
	ids := lineageIDsOf(report.Rows)
	if len(ids) == 0 {
		return nil
	}
	d := &sqlDialect{pg: true}
	rows, err := r.db.Query(lastEventQuery(d, ids), d.args...)
	if err != nil {
		return fmt.Errorf("last events: %w", err)
	}
	defer rows.Close()
	events, err := scanLastEvents(rows)
	if err != nil {
		return err
	}
	applyLastEvents(report.Rows, events)
	return nil
}

// CountTargetScans is the DENOMINATOR of the "seen in 2 of 5 scans" bar.
func (r *PostgresLineageRepo) CountTargetScans(targetKey string, scans []string) (int, error) {
	keys := r.TargetReadKeys(targetKey)
	if len(keys) == 0 {
		return 0, nil
	}
	d := &sqlDialect{pg: true}
	query := countScansQuery(d, keys, scans)
	var n int
	if err := r.db.QueryRow(query, d.args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("count target scans: %w", err)
	}
	return n, nil
}

// SeenInAudits lists the audits that saw one finding — reported it, or
// re-read its evidence. This is the ONE read allowed to touch the `findings`
// table, and it serves one lineage row at a time on the detail page.
func (r *PostgresLineageRepo) SeenInAudits(l *model.FindingLineage) ([]string, error) {
	d := &sqlDialect{pg: true}
	query, ok := seenInQuery(d, l)
	if !ok {
		return []string{}, nil
	}
	rows, err := r.db.Query(query, d.args...)
	if err != nil {
		return nil, fmt.Errorf("seen-in audits: %w", err)
	}
	defer rows.Close()
	return scanSeenIn(rows)
}

// scanPGTargetSummaries reads the scan-derived half of the target list.
func scanPGTargetSummaries(rows *sql.Rows) ([]model.TargetSummary, error) {
	var out []model.TargetSummary
	for rows.Next() {
		var t model.TargetSummary
		if err := rows.Scan(&t.TargetKey, &t.LastAuditID, &t.LastScanAt, &t.RootPath, &t.GitURL, &t.ScanCount); err != nil {
			return nil, fmt.Errorf("scan target: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// scanPGTargetScans reads one target's history. `types` is a TEXT[] column
// here, decoded through pq.StringArray, and normalised to a non-nil slice.
func scanPGTargetScans(rows *sql.Rows) ([]model.TargetScan, error) {
	var out []model.TargetScan
	for rows.Next() {
		var s model.TargetScan
		types := pq.StringArray{}
		if err := rows.Scan(&s.AuditID, &s.CreatedAt, &s.Path, &s.GitBranch, &types); err != nil {
			return nil, fmt.Errorf("scan target scan: %w", err)
		}
		s.Types = []string(types)
		if s.Types == nil {
			s.Types = []string{}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
