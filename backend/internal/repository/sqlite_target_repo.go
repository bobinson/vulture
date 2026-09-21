package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 §10.1, SQLite half. See postgres_target_repo.go for the shape
// of each query and target_repo.go for the predicates the two dialects share.
//
// SQLite is not a second-class store here: it is the default for a local dev
// stack and the ONLY store the native installer ships, so a Postgres-only
// aggregate leaves both with a 500 on the page this feature exists to add.

// ListTargets returns every codebase this installation has scanned.
func (r *SQLiteLineageRepo) ListTargets() ([]model.TargetSummary, error) {
	rows, err := r.db.Query(`
		SELECT target_key, audit_id, created_at, root_path, git_url, scan_count
		  FROM (
		    SELECT COALESCE(s.target_key,'')                                        AS target_key,
		           a.id                                                             AS audit_id,
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
	out, err := scanSQLiteTargetSummaries(rows)
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
func (r *SQLiteLineageRepo) targetCounts() (map[string]model.TargetSummary, error) {
	d := &sqlDialect{}
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
func (r *SQLiteLineageRepo) TargetScans(targetKey string) ([]model.TargetScan, error) {
	keys := r.TargetReadKeys(targetKey)
	if len(keys) == 0 {
		return nil, nil
	}
	d := &sqlDialect{}
	in := d.inList(keys)
	rows, err := r.db.Query(`
		SELECT a.id, a.created_at, COALESCE(s.path,''), COALESCE(s.git_branch,''), COALESCE(a.types,'[]')
		  FROM audits a JOIN sources s ON a.source_id = s.id
		 WHERE COALESCE(s.target_key,'') IN `+in+`
		 ORDER BY a.created_at DESC, a.id DESC`, d.args...)
	if err != nil {
		return nil, fmt.Errorf("target scans: %w", err)
	}
	defer rows.Close()
	out, err := scanSQLiteTargetScans(rows)
	if err != nil {
		return nil, err
	}
	return r.attachTierCounts(keys, out)
}

// attachTierCounts fills the det/llm split for every scan in ONE query. Per
// scan it would be a query per rail entry — the N+1 this endpoint cannot
// afford on a target with a long history.
func (r *SQLiteLineageRepo) attachTierCounts(keys []string, scans []model.TargetScan) ([]model.TargetScan, error) {
	if len(scans) == 0 {
		return scans, nil
	}
	d := &sqlDialect{}
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
// the last event for the ids ON THE PAGE. Loading the rows to filter or count
// them in Go is the mistake this shape exists to rule out.
func (r *SQLiteLineageRepo) AggregateByTarget(q model.AggregateQuery) (*model.AggregateReport, error) {
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

func (r *SQLiteLineageRepo) readAggregateTiles(keys []string, q model.AggregateQuery, report *model.AggregateReport) error {
	d := &sqlDialect{}
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

func (r *SQLiteLineageRepo) readAggregateTotal(keys []string, q model.AggregateQuery, report *model.AggregateReport) error {
	d := &sqlDialect{}
	where := reportFilterSQL(d, keys, q)
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM finding_lineage WHERE `+where, d.args...).
		Scan(&report.Total); err != nil {
		return fmt.Errorf("aggregate total: %w", err)
	}
	return nil
}

func (r *SQLiteLineageRepo) readAggregatePage(keys []string, q model.AggregateQuery, report *model.AggregateReport) error {
	d := &sqlDialect{}
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
		var firstFound, latestFound string
		if err := rows.Scan(&s.id, &s.refNumber, &s.severity, &s.category, &s.title, &s.filePath, &s.sourcePath,
			&s.lineStart, &s.provenance, &s.seenCount, &s.status, &firstFound, &latestFound); err != nil {
			return fmt.Errorf("scan aggregate row: %w", err)
		}
		s.firstFoundAt, _ = time.Parse(time.RFC3339, firstFound)
		s.latestFoundAt, _ = time.Parse(time.RFC3339, latestFound)
		report.Rows = append(report.Rows, newAggregateRow(s))
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("aggregate page: %w", err)
	}
	return nil
}

// attachLastEvents resolves the most recent event for the rows ON THE PAGE, in
// one statement. lineage_events is not `findings` and this join is allowed —
// but it is still bounded to the page, because the timeline of every row of a
// target is a table scan nobody asked for.
func (r *SQLiteLineageRepo) attachLastEvents(report *model.AggregateReport) error {
	ids := lineageIDsOf(report.Rows)
	if len(ids) == 0 {
		return nil
	}
	d := &sqlDialect{}
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

// CountTargetScans is the DENOMINATOR of the "seen in 2 of 5 scans" bar: how
// many scans are in the selection, which is a property of the SELECTION and
// not of any row.
func (r *SQLiteLineageRepo) CountTargetScans(targetKey string, scans []string) (int, error) {
	keys := r.TargetReadKeys(targetKey)
	if len(keys) == 0 {
		return 0, nil
	}
	d := &sqlDialect{}
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
func (r *SQLiteLineageRepo) SeenInAudits(l *model.FindingLineage) ([]string, error) {
	d := &sqlDialect{}
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

// scanTargetCounts reduces the grouped lineage counts into a per-target map.
func scanTargetCounts(rows *sql.Rows) (map[string]model.TargetSummary, error) {
	out := map[string]model.TargetSummary{}
	for rows.Next() {
		var t model.TargetSummary
		if err := rows.Scan(&t.TargetKey, &t.ActiveCount, &t.UnconfirmedCount, &t.FixedCount); err != nil {
			return nil, fmt.Errorf("scan target counts: %w", err)
		}
		out[t.TargetKey] = t
	}
	return out, rows.Err()
}

// scanSQLiteTargetSummaries reads the scan-derived half of the target list.
// SQLite stores created_at as RFC3339 text, so the timestamp is parsed here
// rather than scanned.
func scanSQLiteTargetSummaries(rows *sql.Rows) ([]model.TargetSummary, error) {
	var out []model.TargetSummary
	for rows.Next() {
		var t model.TargetSummary
		var createdAt string
		if err := rows.Scan(&t.TargetKey, &t.LastAuditID, &createdAt, &t.RootPath, &t.GitURL, &t.ScanCount); err != nil {
			return nil, fmt.Errorf("scan target: %w", err)
		}
		t.LastScanAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, t)
	}
	return out, rows.Err()
}

// scanSQLiteTargetScans reads one target's history. `types` is a JSON array on
// SQLite (a TEXT[] column on Postgres) and is normalised to a non-nil slice
// either way, because the rail renders it as a list.
func scanSQLiteTargetScans(rows *sql.Rows) ([]model.TargetScan, error) {
	var out []model.TargetScan
	for rows.Next() {
		var s model.TargetScan
		var createdAt, typesJSON string
		if err := rows.Scan(&s.AuditID, &createdAt, &s.Path, &s.GitBranch, &typesJSON); err != nil {
			return nil, fmt.Errorf("scan target scan: %w", err)
		}
		s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		_ = json.Unmarshal([]byte(typesJSON), &s.Types)
		if s.Types == nil {
			s.Types = []string{}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
