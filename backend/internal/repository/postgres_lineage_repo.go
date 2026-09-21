package repository

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/vulture/backend/internal/model"
)

// The SELECT lists every read in this file shares. See lineageSelectCols for
// why they are computed once instead of copied per query.
var (
	pgLineageCols   = lineageSelectCols("", true)
	pgLineageColsFL = lineageSelectCols("fl.", true)
)

// PostgresLineageRepo implements LineageRepository for PostgreSQL.
type PostgresLineageRepo struct {
	db *sql.DB
}

// NewPostgresLineageRepo creates a new PostgreSQL lineage repository.
func NewPostgresLineageRepo(db *sql.DB) *PostgresLineageRepo {
	return &PostgresLineageRepo{db: db}
}

func (r *PostgresLineageRepo) UpsertLineage(l *model.FindingLineage) error {
	if l.ID == "" {
		l.ID = generateLineageUUID()
	}
	now := time.Now().UTC()
	if l.CreatedAt.IsZero() {
		l.CreatedAt = now
	}
	if l.UpdatedAt.IsZero() {
		l.UpdatedAt = now
	}
	// ref_number is assigned by a Postgres sequence (migration 016) so
	// concurrent inserts can't collide. We omit ref_number from the INSERT
	// column list and rely on the column DEFAULT (nextval). RETURNING
	// reports back the value Postgres actually stored.
	//
	// BUG FIX 2026-05-29: we also RETURNING id. The ON CONFLICT DO UPDATE
	// branch keeps the pre-existing row's id — but the caller had
	// generated a fresh UUID at l.ID = generateLineageUUID() above, which
	// is NOT the id of the row that actually exists in the table. Without
	// the RETURNING id + Scan, callers proceeding to AddEvent(LineageID:
	// l.ID, ...) hit a foreign-key violation because the local UUID is
	// phantom. This race fires under concurrent persistence of findings
	// sharing a fingerprint (e.g. CWE agent emitting many findings per
	// fingerprint, persisted in parallel).
	err := r.db.QueryRow(`
		INSERT INTO finding_lineage (
			id, fingerprint, source_path, agent_type, current_status,
			notes, ticket_url, first_audit_id, first_found_at, first_commit,
			latest_audit_id, latest_found_at, latest_commit,
			fixed_audit_id, fixed_at, fixed_commit,
			severity, category, title, file_path, created_at, updated_at,
			provenance, quote_hash, fingerprint_v2, git_branch, seen_count, last_seen_audit_id,
			evidence_line_start, evidence_line_end, target_key
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31)
		ON CONFLICT (fingerprint, source_path, agent_type) DO UPDATE SET
			latest_audit_id = $11, latest_found_at = $12, latest_commit = $13, updated_at = now(),
			provenance = $23, quote_hash = $24, fingerprint_v2 = $25, git_branch = $26,
			evidence_line_start = $29, evidence_line_end = $30,
			target_key = COALESCE($31, finding_lineage.target_key),
			file_path = $20
		RETURNING id, ref_number`,
		l.ID, l.Fingerprint, l.SourcePath, l.AgentType, string(l.CurrentStatus),
		l.Notes, l.TicketURL, l.FirstAuditID, l.FirstFoundAt, l.FirstCommit,
		nullIfEmpty(l.LatestAuditID), l.LatestFoundAt, l.LatestCommit,
		nullIfEmpty(l.FixedAuditID), l.FixedAt, l.FixedCommit,
		l.Severity, l.Category, l.Title, l.FilePath, l.CreatedAt, l.UpdatedAt,
		// Feature 0091. On CONFLICT these four are refreshed — as is file_path,
		// because the scan that re-found the finding just read that file and
		// its path is the one the next scan's scope check can resolve (§6.5);
		// left frozen, a row first seen under another mount is unplaceable for
		// ever and can never close again. seen_count is NOT refreshed: it is
		// owned by MarkSeen/ApplyEvidence, so an upsert cannot make one scan
		// count twice.
		l.Provenance, l.QuoteHash, l.FingerprintV2, l.GitBranch,
		defaultSeenCount(l.SeenCount), nullIfEmpty(l.LastSeenAuditID),
		l.EvidenceLineStart, l.EvidenceLineEnd, nullIfEmpty(l.TargetKey),
	).Scan(&l.ID, &l.RefNumber)
	if isTargetIdentityConflict(err) {
		// The row already exists under this target's OTHER identity key, so
		// the update branch is what this write always meant. See
		// lineage_target_conflict.go for why the upsert's own ON CONFLICT
		// cannot cover it.
		return r.updateOnTargetConflict(l, err)
	}
	if err != nil {
		return fmt.Errorf("upsert lineage: %w", err)
	}
	l.Ref = l.FormatRef()
	return nil
}

// updateOnTargetConflict applies the write to the row uq_lineage_target says
// already holds this identity. The SET list mirrors the upsert's ON CONFLICT
// DO UPDATE branch exactly: the two are the same operation reached two ways,
// and a column that drifted out of one of them would be refreshed on some
// scans and not others.
func (r *PostgresLineageRepo) updateOnTargetConflict(l *model.FindingLineage, cause error) error {
	id, ref, findErr := findTargetConflictRow(r.db, l, true)
	if findErr != nil {
		return fmt.Errorf("upsert lineage: %w (after %v)", findErr, cause)
	}
	if id == "" {
		// Merged or deleted between the failed write and this read. Report
		// the original conflict rather than inventing an outcome.
		return fmt.Errorf("upsert lineage: %w", cause)
	}
	if _, err := r.db.Exec(`
		UPDATE finding_lineage SET
			latest_audit_id = $2, latest_found_at = $3, latest_commit = $4, updated_at = now(),
			provenance = $5, quote_hash = $6, fingerprint_v2 = $7, git_branch = $8,
			evidence_line_start = $9, evidence_line_end = $10,
			target_key = COALESCE($11, target_key),
			file_path = $12
		WHERE id = $1`,
		id, nullIfEmpty(l.LatestAuditID), l.LatestFoundAt, l.LatestCommit,
		l.Provenance, l.QuoteHash, l.FingerprintV2, l.GitBranch,
		l.EvidenceLineStart, l.EvidenceLineEnd, nullIfEmpty(l.TargetKey), l.FilePath,
	); err != nil {
		return fmt.Errorf("upsert lineage on target conflict: %w", err)
	}
	l.ID = id
	l.RefNumber = ref
	l.Ref = l.FormatRef()
	return nil
}

func (r *PostgresLineageRepo) GetLineage(id string) (*model.FindingLineage, error) {
	row := r.db.QueryRow(`
		SELECT `+pgLineageCols+`
		FROM finding_lineage WHERE id = $1`, id)
	return scanPostgresLineage(row)
}

func (r *PostgresLineageRepo) GetLineageByFingerprint(fingerprint, sourcePath, agentType string) (*model.FindingLineage, error) {
	row := r.db.QueryRow(`
		SELECT `+pgLineageCols+`
		FROM finding_lineage
		WHERE fingerprint = $1 AND source_path = $2 AND agent_type = $3`, fingerprint, sourcePath, agentType)
	return scanPostgresLineage(row)
}

// GetLineageByFingerprints fetches lineage records for multiple fingerprints in a single query.
func (r *PostgresLineageRepo) GetLineageByFingerprints(fingerprints []string, sourcePath string) (map[string]*model.FindingLineage, error) {
	if len(fingerprints) == 0 {
		return nil, nil
	}
	rows, err := r.db.Query(`
		SELECT `+pgLineageCols+`
		FROM finding_lineage
		WHERE fingerprint = ANY($1) AND source_path = $2`,
		pq.Array(fingerprints), sourcePath,
	)
	if err != nil {
		return nil, fmt.Errorf("get lineage by fingerprints: %w", err)
	}
	defer rows.Close()
	lineages, err := scanPostgresLineageRows(rows)
	if err != nil {
		return nil, err
	}
	result := make(map[string]*model.FindingLineage, len(lineages))
	for i := range lineages {
		// Key by fingerprint+agentType to match the individual lookup pattern
		key := lineages[i].Fingerprint + "|" + lineages[i].AgentType
		result[key] = &lineages[i]
	}
	return result, nil
}

// ListBySourcePath returns the lineage register for one scanned path. See the
// SQLite twin for why an EMPTY status filter means the ACTIVE set from feature
// 0091 onward, and how the archive is still reached.
func (r *PostgresLineageRepo) ListBySourcePath(sourcePath, status string, limit, offset int) ([]model.FindingLineage, error) {
	if limit <= 0 {
		limit = 20
	}
	var rows *sql.Rows
	var err error
	if status == "" {
		// The status placeholders occupy $2..$1+N, so LIMIT/OFFSET follow
		// them. Computed rather than written out because N is whatever
		// model.ActiveLineageStatuses says it is, and a hardcoded $6/$7 would
		// break silently the day a status is added to that one list.
		n := len(model.ActiveLineageStatuses())
		rows, err = r.db.Query(fmt.Sprintf(`
			SELECT `+pgLineageCols+`
			FROM finding_lineage
			WHERE source_path = $1 AND current_status IN `+activeStatusIn(true, 2)+notMerged+`
			ORDER BY updated_at DESC LIMIT $%d OFFSET $%d`, n+2, n+3),
			append(append([]interface{}{sourcePath}, activeStatusArgs()...), limit, offset)...)
	} else {
		rows, err = r.db.Query(`
			SELECT `+pgLineageCols+`
			FROM finding_lineage WHERE source_path = $1 AND current_status = $2`+notMerged+`
			ORDER BY updated_at DESC LIMIT $3 OFFSET $4`, sourcePath, status, limit, offset)
	}
	if err != nil {
		return nil, fmt.Errorf("list lineage by source: %w", err)
	}
	defer rows.Close()
	return scanPostgresLineageRows(rows)
}

func (r *PostgresLineageRepo) ListByAudit(auditID string) ([]model.FindingLineage, error) {
	rows, err := r.db.Query(`
		SELECT `+pgLineageColsFL+`
		FROM finding_lineage fl
		INNER JOIN findings f ON f.fingerprint = fl.fingerprint
			AND f.agent_type = fl.agent_type
		WHERE f.audit_id = $1 AND fl.merged_into IS NULL
		GROUP BY fl.id
		ORDER BY fl.updated_at DESC`, auditID)
	if err != nil {
		return nil, fmt.Errorf("list lineage by audit: %w", err)
	}
	defer rows.Close()
	return scanPostgresLineageRows(rows)
}

func (r *PostgresLineageRepo) UpdateStatus(id string, status string, notes string, ticketURL string) error {
	_, err := r.db.Exec(`
		UPDATE finding_lineage SET current_status = $1, notes = $2, ticket_url = $3, updated_at = now()
		WHERE id = $4`, status, notes, ticketURL, id)
	if err != nil {
		return fmt.Errorf("update lineage status: %w", err)
	}
	return nil
}

func (r *PostgresLineageRepo) MarkFixed(id, auditID, commit string) error {
	_, err := r.db.Exec(`
		UPDATE finding_lineage SET current_status = 'fixed',
			fixed_audit_id = $1, fixed_at = now(), fixed_commit = $2, updated_at = now()
		WHERE id = $3`, nullIfEmpty(auditID), commit, id)
	if err != nil {
		return fmt.Errorf("mark lineage fixed: %w", err)
	}
	return nil
}

func (r *PostgresLineageRepo) MarkRegression(id, auditID, commit string) error {
	_, err := r.db.Exec(`
		UPDATE finding_lineage SET current_status = 'regression',
			fixed_audit_id = NULL, fixed_at = NULL, fixed_commit = NULL,
			latest_audit_id = $1, latest_found_at = now(), latest_commit = $2, updated_at = now()
		WHERE id = $3`, nullIfEmpty(auditID), commit, id)
	if err != nil {
		return fmt.Errorf("mark lineage regression: %w", err)
	}
	return nil
}

func (r *PostgresLineageRepo) GetActiveBySourcePath(sourcePath, agentType string) ([]model.FindingLineage, error) {
	args := append([]interface{}{sourcePath, agentType}, activeStatusArgs()...)
	rows, err := r.db.Query(`
		SELECT `+pgLineageCols+`
		FROM finding_lineage
		WHERE source_path = $1 AND agent_type = $2 AND current_status IN `+activeStatusIn(true, 3)+notMerged, args...)
	if err != nil {
		return nil, fmt.Errorf("get active lineage: %w", err)
	}
	defer rows.Close()
	return scanPostgresLineageRows(rows)
}

// ActiveByTarget is the target-keyed twin of GetActiveBySourcePath (feature
// 0091 §7). See the interface for why the key changed. It is served by
// idx_lineage_active_target, the partial index migration 027 step 6 builds
// over exactly model.ActiveLineageStatuses.
func (r *PostgresLineageRepo) ActiveByTarget(targetKey, agentType string) ([]model.FindingLineage, error) {
	if targetKey == "" {
		return nil, nil
	}
	args := append([]interface{}{targetKey, agentType}, activeStatusArgs()...)
	rows, err := r.db.Query(`
		SELECT `+pgLineageCols+`
		FROM finding_lineage
		WHERE target_key = $1 AND agent_type = $2 AND current_status IN `+activeStatusIn(true, 3)+notMerged, args...)
	if err != nil {
		return nil, fmt.Errorf("get active lineage by target: %w", err)
	}
	defer rows.Close()
	return scanPostgresLineageRows(rows)
}

// GetLineageByFingerprintsForTarget resolves, in one query, which rows of a
// target the findings a scan just reported already own — under EITHER
// identity. See the interface for why both are needed.
func (r *PostgresLineageRepo) GetLineageByFingerprintsForTarget(fingerprints []string, targetKey string) (map[string]*model.FindingLineage, error) {
	if len(fingerprints) == 0 || targetKey == "" {
		return nil, nil
	}
	rows, err := r.db.Query(`
		SELECT `+pgLineageCols+`
		FROM finding_lineage
		WHERE target_key = $1
		  AND (fingerprint = ANY($2) OR fingerprint_v2 = ANY($2))`+notMerged,
		targetKey, pq.Array(fingerprints),
	)
	if err != nil {
		return nil, fmt.Errorf("get lineage by fingerprints for target: %w", err)
	}
	defer rows.Close()
	lineages, err := scanPostgresLineageRows(rows)
	if err != nil {
		return nil, err
	}
	return indexLineageByIdentity(lineages), nil
}

func (r *PostgresLineageRepo) AddEvent(e *model.LineageEvent) error {
	if e.ID == "" {
		e.ID = generateLineageUUID()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	_, err := r.db.Exec(`
		INSERT INTO lineage_events (id, lineage_id, event_type, audit_id, git_commit, git_branch, old_status, new_status, notes, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		e.ID, e.LineageID, string(e.EventType), nullIfEmpty(e.AuditID), e.GitCommit, e.GitBranch,
		e.OldStatus, e.NewStatus, e.Notes, e.CreatedAt)
	if err != nil {
		return fmt.Errorf("add lineage event: %w", err)
	}
	return nil
}

func (r *PostgresLineageRepo) GetEvents(lineageID string) ([]model.LineageEvent, error) {
	rows, err := r.db.Query(`
		SELECT id, lineage_id, event_type, COALESCE(audit_id::text,''), COALESCE(git_commit,''),
			COALESCE(git_branch,''), COALESCE(old_status,''), COALESCE(new_status,''),
			COALESCE(notes,''), created_at
		FROM lineage_events WHERE lineage_id = $1
		ORDER BY created_at ASC`, lineageID)
	if err != nil {
		return nil, fmt.Errorf("get lineage events: %w", err)
	}
	defer rows.Close()
	var events []model.LineageEvent
	for rows.Next() {
		var e model.LineageEvent
		if err := rows.Scan(&e.ID, &e.LineageID, &e.EventType, &e.AuditID, &e.GitCommit,
			&e.GitBranch, &e.OldStatus, &e.NewStatus, &e.Notes, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan lineage event: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// pgLineageScanner is the one place the SELECT list of
// lineageSelectCols("", true) is turned back into a struct, for the same
// reason its SQLite twin exists: eleven new columns across seven queries is
// where a hand-copied scan list drifts.
type pgLineageScanner struct {
	l                      model.FindingLineage
	latestFoundAt, fixedAt sql.NullTime
}

func (s *pgLineageScanner) targets() []interface{} {
	l := &s.l
	return []interface{}{
		&l.ID, &l.Fingerprint, &l.SourcePath, &l.AgentType, &l.CurrentStatus,
		&l.Notes, &l.TicketURL,
		&l.FirstAuditID, &l.FirstFoundAt, &l.FirstCommit,
		&l.LatestAuditID, &s.latestFoundAt, &l.LatestCommit,
		&l.FixedAuditID, &s.fixedAt, &l.FixedCommit,
		&l.Severity, &l.Category, &l.Title, &l.FilePath, &l.CreatedAt, &l.UpdatedAt,
		&l.RefNumber,
		&l.TargetKey, &l.FingerprintV2, &l.GitBranch, &l.Provenance, &l.QuoteHash,
		&l.EvidenceLineStart, &l.EvidenceLineEnd, &l.EvidenceFileHash,
		&l.SeenCount, &l.LastSeenAuditID, &l.MergedInto,
	}
}

func (s *pgLineageScanner) finish() *model.FindingLineage {
	l := &s.l
	if s.latestFoundAt.Valid {
		l.LatestFoundAt = &s.latestFoundAt.Time
	}
	if s.fixedAt.Valid {
		l.FixedAt = &s.fixedAt.Time
	}
	if l.RefNumber > 0 {
		l.Ref = l.FormatRef()
	}
	return l
}

func scanPostgresLineage(row *sql.Row) (*model.FindingLineage, error) {
	var s pgLineageScanner
	err := row.Scan(s.targets()...)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan lineage: %w", err)
	}
	return s.finish(), nil
}

func scanPostgresLineageRows(rows *sql.Rows) ([]model.FindingLineage, error) {
	var result []model.FindingLineage
	for rows.Next() {
		var s pgLineageScanner
		if err := rows.Scan(s.targets()...); err != nil {
			return nil, fmt.Errorf("scan lineage row: %w", err)
		}
		result = append(result, *s.finish())
	}
	return result, rows.Err()
}

// nullIfEmpty returns nil for empty strings, allowing PostgreSQL to store NULL
// for nullable UUID columns instead of rejecting an empty string.
func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func generateLineageUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 2
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// GetRecentlyFixedBySourcePath implements the bounded fixed-row re-check
// (feature 0091 §6.3). See the SQLite twin for why the window exists.
func (r *PostgresLineageRepo) GetRecentlyFixedBySourcePath(sourcePath, agentType string, auditWindow int) ([]model.FindingLineage, error) {
	if auditWindow <= 0 {
		return nil, nil
	}
	rows, err := r.db.Query(`
		SELECT `+pgLineageCols+`
		FROM finding_lineage
		WHERE source_path = $1 AND agent_type = $2 AND current_status = 'fixed'`+notMerged+`
		  AND fixed_audit_id IS NOT NULL
		  AND fixed_audit_id IN (
			SELECT fixed_audit_id FROM finding_lineage
			WHERE source_path = $1 AND agent_type = $2 AND current_status = 'fixed'
			  AND fixed_audit_id IS NOT NULL
			GROUP BY fixed_audit_id
			ORDER BY MAX(fixed_at) DESC
			LIMIT $3)`, sourcePath, agentType, auditWindow)
	if err != nil {
		return nil, fmt.Errorf("get recently fixed lineage: %w", err)
	}
	defer rows.Close()
	return scanPostgresLineageRows(rows)
}

// RecentlyFixedByTarget is the target-keyed twin. Same window rule, same
// bound; only the partition changes. See the interface for why the path-keyed
// one could not serve it.
func (r *PostgresLineageRepo) RecentlyFixedByTarget(targetKey, agentType string, auditWindow int) ([]model.FindingLineage, error) {
	if auditWindow <= 0 || targetKey == "" {
		return nil, nil
	}
	rows, err := r.db.Query(`
		SELECT `+pgLineageCols+`
		FROM finding_lineage
		WHERE target_key = $1 AND agent_type = $2 AND current_status = 'fixed'`+notMerged+`
		  AND fixed_audit_id IS NOT NULL
		  AND fixed_audit_id IN (
			SELECT fixed_audit_id FROM finding_lineage
			WHERE target_key = $1 AND agent_type = $2 AND current_status = 'fixed'
			  AND fixed_audit_id IS NOT NULL
			GROUP BY fixed_audit_id
			ORDER BY MAX(fixed_at) DESC
			LIMIT $3)`, targetKey, agentType, auditWindow)
	if err != nil {
		return nil, fmt.Errorf("get recently fixed lineage by target: %w", err)
	}
	defer rows.Close()
	return scanPostgresLineageRows(rows)
}

func (r *PostgresLineageRepo) MarkUnconfirmed(id, auditID string) error {
	_, err := r.db.Exec(`
		UPDATE finding_lineage SET current_status = 'unconfirmed',
			last_seen_audit_id = $1, updated_at = now()
		WHERE id = $2`, nullIfEmpty(auditID), id)
	if err != nil {
		return fmt.Errorf("mark lineage unconfirmed: %w", err)
	}
	return nil
}

func (r *PostgresLineageRepo) MarkSeen(id, auditID string) error {
	_, err := r.db.Exec(`
		UPDATE finding_lineage SET seen_count = COALESCE(seen_count, 1) + 1,
			last_seen_audit_id = $1, updated_at = now()
		WHERE id = $2`, nullIfEmpty(auditID), id)
	if err != nil {
		return fmt.Errorf("mark lineage seen: %w", err)
	}
	return nil
}

func (r *PostgresLineageRepo) ApplyEvidence(id string, ev LineageEvidenceUpdate) error {
	sets := "evidence_file_hash = $1, last_seen_audit_id = $2, updated_at = now()"
	args := []interface{}{ev.FileHash, nullIfEmpty(ev.AuditID)}
	if ev.IncrementSeen {
		sets += ", seen_count = COALESCE(seen_count, 1) + 1"
	}
	if ev.UpdateWindow {
		sets += fmt.Sprintf(", evidence_line_start = $%d, evidence_line_end = $%d", len(args)+1, len(args)+2)
		args = append(args, ev.LineStart, ev.LineEnd)
	}
	args = append(args, id)
	q := fmt.Sprintf(`UPDATE finding_lineage SET %s WHERE id = $%d`, sets, len(args))
	if _, err := r.db.Exec(q, args...); err != nil {
		return fmt.Errorf("apply lineage evidence: %w", err)
	}
	return nil
}
