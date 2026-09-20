package repository

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/vulture/backend/internal/model"
)

// The SELECT lists every read in this file shares. See lineageSelectCols for
// why they are computed once instead of copied per query.
var (
	sqliteLineageCols   = lineageSelectCols("", false)
	sqliteLineageColsFL = lineageSelectCols("fl.", false)
)

// SQLiteLineageRepo implements LineageRepository for SQLite.
type SQLiteLineageRepo struct {
	db *sql.DB
}

// NewSQLiteLineageRepo creates a new SQLite lineage repository.
func NewSQLiteLineageRepo(db *sql.DB) *SQLiteLineageRepo {
	return &SQLiteLineageRepo{db: db}
}

func (r *SQLiteLineageRepo) UpsertLineage(l *model.FindingLineage) error {
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

	// Check if lineage already exists
	existing, err := r.GetLineageByFingerprint(l.Fingerprint, l.SourcePath, l.AgentType)
	if err != nil {
		return fmt.Errorf("upsert lineage check: %w", err)
	}
	if existing != nil {
		return r.updateLineageRow(l, existing.ID, existing.RefNumber, now)
	}

	// Insert new
	var latestFoundAt, fixedAt string
	if l.LatestFoundAt != nil {
		latestFoundAt = l.LatestFoundAt.Format(time.RFC3339)
	}
	if l.FixedAt != nil {
		fixedAt = l.FixedAt.Format(time.RFC3339)
	}

	// Assign next ref_number atomically within a transaction.
	// SQLite serializes writes, but the SELECT+INSERT must be in the same
	// transaction to prevent interleaving from the connection pool.
	tx, txErr := r.db.Begin()
	if txErr != nil {
		return fmt.Errorf("begin lineage insert tx: %w", txErr)
	}
	defer func() { _ = tx.Rollback() }()

	var nextRef int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(ref_number), 0) + 1 FROM finding_lineage`).Scan(&nextRef); err != nil {
		return fmt.Errorf("next ref_number: %w", err)
	}
	l.RefNumber = nextRef
	l.Ref = l.FormatRef()

	_, err = tx.Exec(`
		INSERT INTO finding_lineage (
			id, fingerprint, source_path, agent_type, current_status,
			notes, ticket_url, first_audit_id, first_found_at, first_commit,
			latest_audit_id, latest_found_at, latest_commit,
			fixed_audit_id, fixed_at, fixed_commit,
			severity, category, title, file_path, created_at, updated_at,
			ref_number,
			provenance, quote_hash, fingerprint_v2, git_branch, target_key,
			seen_count, last_seen_audit_id,
			evidence_line_start, evidence_line_end
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		l.ID, l.Fingerprint, l.SourcePath, l.AgentType, string(l.CurrentStatus),
		l.Notes, l.TicketURL, l.FirstAuditID, l.FirstFoundAt.Format(time.RFC3339), l.FirstCommit,
		l.LatestAuditID, nullIfEmpty(latestFoundAt), l.LatestCommit,
		l.FixedAuditID, nullIfEmpty(fixedAt), l.FixedCommit,
		l.Severity, l.Category, l.Title, l.FilePath,
		l.CreatedAt.Format(time.RFC3339), l.UpdatedAt.Format(time.RFC3339),
		l.RefNumber,
		l.Provenance, l.QuoteHash, l.FingerprintV2, l.GitBranch, nullIfEmpty(l.TargetKey),
		defaultSeenCount(l.SeenCount), nullIfEmpty(l.LastSeenAuditID),
		l.EvidenceLineStart, l.EvidenceLineEnd,
	)
	if isTargetIdentityConflict(err) {
		// The row already exists under this target's OTHER identity key. See
		// lineage_target_conflict.go: the read above is keyed on
		// (fingerprint, source_path, agent_type) and cannot see it, and
		// without this the finding would silently end the scan with no
		// lineage row at all. Roll the insert back first — the transaction is
		// aborted by the constraint and the update is a separate write.
		_ = tx.Rollback()
		return r.updateOnTargetConflict(l, now, err)
	}
	if err != nil {
		return fmt.Errorf("insert lineage: %w", err)
	}
	return tx.Commit()
}

// updateOnTargetConflict applies the write to the row uq_lineage_target says
// already holds this identity.
func (r *SQLiteLineageRepo) updateOnTargetConflict(l *model.FindingLineage,
	now time.Time, cause error) error {
	id, ref, findErr := findTargetConflictRow(r.db, l, false)
	if findErr != nil {
		return fmt.Errorf("insert lineage: %w (after %v)", findErr, cause)
	}
	if id == "" {
		// Merged or deleted between the failed write and this read. Report
		// the original conflict rather than inventing an outcome.
		return fmt.Errorf("insert lineage: %w", cause)
	}
	return r.updateLineageRow(l, id, ref, now)
}

// updateLineageRow is the shared update branch: one definition reached both by
// the ordinary (fingerprint, source_path, agent_type) hit and by the
// target-identity conflict recovery. Kept in one place because the two are
// the same operation reached two ways, and a column that drifted out of one
// of them would be refreshed on some scans and not others.
//
// Feature 0091: the identity/tier metadata is refreshed alongside the "last
// seen" columns. provenance decides which closure rule the row obeys and
// quote_hash is what makes it checkable at all, so a row created before the
// agent emitted either must be able to acquire them on the next scan that
// re-finds the finding — otherwise a pre-0091 row is permanently
// unconfirmable. seen_count is NOT touched here: it is owned by
// MarkSeen/ApplyEvidence, so a single scan cannot count twice.
//
// file_path is refreshed for the same reason and matters most under target
// identity: the scan that re-found the finding just read that file, so its
// path is the one the NEXT scan's scope check can resolve. Left frozen, a row
// first seen under another mount is unplaceable for ever and can never close
// again (§6.5).
func (r *SQLiteLineageRepo) updateLineageRow(l *model.FindingLineage,
	id string, ref int, now time.Time) error {
	var latestFoundAt string
	if l.LatestFoundAt != nil {
		latestFoundAt = l.LatestFoundAt.Format(time.RFC3339)
	}
	if _, err := r.db.Exec(`
		UPDATE finding_lineage SET latest_audit_id = ?, latest_found_at = ?, latest_commit = ?, updated_at = ?,
			provenance = ?, quote_hash = ?, fingerprint_v2 = ?, git_branch = ?, target_key = COALESCE(?, target_key),
			evidence_line_start = ?, evidence_line_end = ?, file_path = ?
		WHERE id = ?`,
		l.LatestAuditID, nullIfEmpty(latestFoundAt), l.LatestCommit, now.Format(time.RFC3339),
		l.Provenance, l.QuoteHash, l.FingerprintV2, l.GitBranch, nullIfEmpty(l.TargetKey),
		l.EvidenceLineStart, l.EvidenceLineEnd, l.FilePath, id); err != nil {
		return fmt.Errorf("update lineage: %w", err)
	}
	l.ID = id
	// The ref belongs to the row, not to the write: a caller that reached the
	// update branch through createNewLineage carries a fresh struct with none,
	// and re-minting one would be the duplicate-VLT-ref defect wearing a
	// different hat.
	if ref != 0 {
		l.RefNumber = ref
		l.Ref = l.FormatRef()
	}
	return nil
}

func (r *SQLiteLineageRepo) GetLineage(id string) (*model.FindingLineage, error) {
	row := r.db.QueryRow(`
		SELECT `+sqliteLineageCols+`
		FROM finding_lineage WHERE id = ?`, id)
	return scanSQLiteLineage(row)
}

func (r *SQLiteLineageRepo) GetLineageByFingerprint(fingerprint, sourcePath, agentType string) (*model.FindingLineage, error) {
	row := r.db.QueryRow(`
		SELECT `+sqliteLineageCols+`
		FROM finding_lineage
		WHERE fingerprint = ? AND source_path = ? AND agent_type = ?`, fingerprint, sourcePath, agentType)
	return scanSQLiteLineage(row)
}

// GetLineageByFingerprints fetches lineage records for multiple fingerprints in a single query.
func (r *SQLiteLineageRepo) GetLineageByFingerprints(fingerprints []string, sourcePath string) (map[string]*model.FindingLineage, error) {
	if len(fingerprints) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(fingerprints))
	args := make([]interface{}, 0, len(fingerprints)+1)
	for i, fp := range fingerprints {
		placeholders[i] = "?"
		args = append(args, fp)
	}
	args = append(args, sourcePath)
	rows, err := r.db.Query(fmt.Sprintf(`
		SELECT `+sqliteLineageCols+`
		FROM finding_lineage
		WHERE fingerprint IN (%s) AND source_path = ?`, strings.Join(placeholders, ",")), args...)
	if err != nil {
		return nil, fmt.Errorf("get lineage by fingerprints: %w", err)
	}
	defer rows.Close()
	lineages, err := scanSQLiteLineageRows(rows)
	if err != nil {
		return nil, err
	}
	result := make(map[string]*model.FindingLineage, len(lineages))
	for i := range lineages {
		key := lineages[i].Fingerprint + "|" + lineages[i].AgentType
		result[key] = &lineages[i]
	}
	return result, nil
}

// ListBySourcePath returns the lineage register for one scanned path.
//
// FEATURE 0091: an EMPTY status filter now means the ACTIVE set
// (model.ActiveLineageStatuses), not "every row ever recorded". Once history
// survives a mount change, the unfiltered list of a long-lived target is
// dominated by rows that are closed — `fixed` by a previous scan, or ruled on
// by a human — and a caller asking "what is outstanding here" was being handed
// the archive. The archive is still reachable: pass the status explicitly
// (`?status=fixed`), which is also how the aggregate report reads it.
func (r *SQLiteLineageRepo) ListBySourcePath(sourcePath, status string, limit, offset int) ([]model.FindingLineage, error) {
	if limit <= 0 {
		limit = 20
	}
	var rows *sql.Rows
	var err error
	if status == "" {
		rows, err = r.db.Query(`
			SELECT `+sqliteLineageCols+`
			FROM finding_lineage
			WHERE source_path = ? AND current_status IN `+activeStatusIn(false, 0)+notMerged+`
			ORDER BY updated_at DESC LIMIT ? OFFSET ?`,
			append(append([]interface{}{sourcePath}, activeStatusArgs()...), limit, offset)...)
	} else {
		rows, err = r.db.Query(`
			SELECT `+sqliteLineageCols+`
			FROM finding_lineage WHERE source_path = ? AND current_status = ?`+notMerged+`
			ORDER BY updated_at DESC LIMIT ? OFFSET ?`, sourcePath, status, limit, offset)
	}
	if err != nil {
		return nil, fmt.Errorf("list lineage by source: %w", err)
	}
	defer rows.Close()
	return scanSQLiteLineageRows(rows)
}

func (r *SQLiteLineageRepo) ListByAudit(auditID string) ([]model.FindingLineage, error) {
	rows, err := r.db.Query(`
		SELECT `+sqliteLineageColsFL+`
		FROM finding_lineage fl
		INNER JOIN findings f ON f.fingerprint = fl.fingerprint
			AND f.agent_type = fl.agent_type
		WHERE f.audit_id = ? AND fl.merged_into IS NULL
		GROUP BY fl.id
		ORDER BY fl.updated_at DESC`, auditID)
	if err != nil {
		return nil, fmt.Errorf("list lineage by audit: %w", err)
	}
	defer rows.Close()
	return scanSQLiteLineageRows(rows)
}

func (r *SQLiteLineageRepo) UpdateStatus(id string, status string, notes string, ticketURL string) error {
	_, err := r.db.Exec(`
		UPDATE finding_lineage SET current_status = ?, notes = ?, ticket_url = ?, updated_at = ?
		WHERE id = ?`, status, notes, ticketURL, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("update lineage status: %w", err)
	}
	return nil
}

func (r *SQLiteLineageRepo) MarkFixed(id, auditID, commit string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := r.db.Exec(`
		UPDATE finding_lineage SET current_status = 'fixed',
			fixed_audit_id = ?, fixed_at = ?, fixed_commit = ?, updated_at = ?
		WHERE id = ?`, auditID, now, commit, now, id)
	if err != nil {
		return fmt.Errorf("mark lineage fixed: %w", err)
	}
	return nil
}

func (r *SQLiteLineageRepo) MarkRegression(id, auditID, commit string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := r.db.Exec(`
		UPDATE finding_lineage SET current_status = 'regression',
			fixed_audit_id = '', fixed_at = NULL, fixed_commit = '',
			latest_audit_id = ?, latest_found_at = ?, latest_commit = ?, updated_at = ?
		WHERE id = ?`, auditID, now, commit, now, id)
	if err != nil {
		return fmt.Errorf("mark lineage regression: %w", err)
	}
	return nil
}

func (r *SQLiteLineageRepo) GetActiveBySourcePath(sourcePath, agentType string) ([]model.FindingLineage, error) {
	args := append([]interface{}{sourcePath, agentType}, activeStatusArgs()...)
	rows, err := r.db.Query(`
		SELECT `+sqliteLineageCols+`
		FROM finding_lineage
		WHERE source_path = ? AND agent_type = ? AND current_status IN `+activeStatusIn(false, 0)+notMerged, args...)
	if err != nil {
		return nil, fmt.Errorf("get active lineage: %w", err)
	}
	defer rows.Close()
	return scanSQLiteLineageRows(rows)
}

// ActiveByTarget is the target-keyed twin of GetActiveBySourcePath (feature
// 0091 §7). See the interface for why the key changed.
func (r *SQLiteLineageRepo) ActiveByTarget(targetKey, agentType string) ([]model.FindingLineage, error) {
	if targetKey == "" {
		return nil, nil
	}
	args := append([]interface{}{targetKey, agentType}, activeStatusArgs()...)
	rows, err := r.db.Query(`
		SELECT `+sqliteLineageCols+`
		FROM finding_lineage
		WHERE target_key = ? AND agent_type = ? AND current_status IN `+activeStatusIn(false, 0)+notMerged, args...)
	if err != nil {
		return nil, fmt.Errorf("get active lineage by target: %w", err)
	}
	defer rows.Close()
	return scanSQLiteLineageRows(rows)
}

// GetLineageByFingerprintsForTarget resolves, in one query, which rows of a
// target the findings a scan just reported already own — under EITHER
// identity. See the interface for why both are needed.
func (r *SQLiteLineageRepo) GetLineageByFingerprintsForTarget(fingerprints []string, targetKey string) (map[string]*model.FindingLineage, error) {
	if len(fingerprints) == 0 || targetKey == "" {
		return nil, nil
	}
	in := "(" + strings.TrimSuffix(strings.Repeat("?,", len(fingerprints)), ",") + ")"
	args := make([]interface{}, 0, 2*len(fingerprints)+1)
	args = append(args, targetKey)
	for range 2 {
		for _, fp := range fingerprints {
			args = append(args, fp)
		}
	}
	rows, err := r.db.Query(`
		SELECT `+sqliteLineageCols+`
		FROM finding_lineage
		WHERE target_key = ?
		  AND (fingerprint IN `+in+` OR COALESCE(fingerprint_v2,'') IN `+in+`)`+notMerged, args...)
	if err != nil {
		return nil, fmt.Errorf("get lineage by fingerprints for target: %w", err)
	}
	defer rows.Close()
	lineages, err := scanSQLiteLineageRows(rows)
	if err != nil {
		return nil, err
	}
	return indexLineageByIdentity(lineages), nil
}

func (r *SQLiteLineageRepo) AddEvent(e *model.LineageEvent) error {
	if e.ID == "" {
		e.ID = generateLineageUUID()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	_, err := r.db.Exec(`
		INSERT INTO lineage_events (id, lineage_id, event_type, audit_id, git_commit, git_branch, old_status, new_status, notes, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.LineageID, string(e.EventType), e.AuditID, e.GitCommit, e.GitBranch,
		e.OldStatus, e.NewStatus, e.Notes, e.CreatedAt.Format(sqliteEventTimeLayout))
	if err != nil {
		return fmt.Errorf("add lineage event: %w", err)
	}
	return nil
}

// sqliteEventTimeLayout is RFC3339 with a FIXED-WIDTH nanosecond fraction.
//
// Events are ordered by created_at, and the aggregate's "last observation" is
// the newest one. Stored to the second (plain RFC3339), every event a scan
// wrote inside one second tied, and the tiebreak fell to the random UUID id —
// the "newest" event was a coin toss, measured as `detected` outranking the
// `reported` written 90 ms later. Fixed width (not RFC3339Nano, which trims
// zeros) keeps the strings lexicographically ordered, which is how SQLite
// compares them. Go's RFC3339 parser accepts a fractional second whether or
// not the layout names one, so the readers are unchanged, and a legacy
// second-precision value still parses.
const sqliteEventTimeLayout = "2006-01-02T15:04:05.000000000Z07:00"

func (r *SQLiteLineageRepo) GetEvents(lineageID string) ([]model.LineageEvent, error) {
	rows, err := r.db.Query(`
		SELECT id, lineage_id, event_type, COALESCE(audit_id,''), COALESCE(git_commit,''),
			COALESCE(git_branch,''), COALESCE(old_status,''), COALESCE(new_status,''),
			COALESCE(notes,''), created_at
		FROM lineage_events WHERE lineage_id = ?
		ORDER BY created_at ASC, rowid ASC`, lineageID)
	if err != nil {
		return nil, fmt.Errorf("get lineage events: %w", err)
	}
	defer rows.Close()
	var events []model.LineageEvent
	for rows.Next() {
		var e model.LineageEvent
		var createdAt string
		if err := rows.Scan(&e.ID, &e.LineageID, &e.EventType, &e.AuditID, &e.GitCommit,
			&e.GitBranch, &e.OldStatus, &e.NewStatus, &e.Notes, &createdAt); err != nil {
			return nil, fmt.Errorf("scan lineage event: %w", err)
		}
		e.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		events = append(events, e)
	}
	return events, rows.Err()
}

// sqliteLineageScanner is the one place the SELECT list of
// lineageSelectCols("", false) is turned back into a struct. Both the
// single-row and the multi-row reader go through it, so the two cannot drift
// out of step with each other or with the column list.
type sqliteLineageScanner struct {
	l                                  model.FindingLineage
	firstFoundAt, createdAt, updatedAt string
	latestFoundAt, fixedAt             sql.NullString
}

// targets returns the scan destinations in column order.
func (s *sqliteLineageScanner) targets() []interface{} {
	l := &s.l
	return []interface{}{
		&l.ID, &l.Fingerprint, &l.SourcePath, &l.AgentType, &l.CurrentStatus,
		&l.Notes, &l.TicketURL,
		&l.FirstAuditID, &s.firstFoundAt, &l.FirstCommit,
		&l.LatestAuditID, &s.latestFoundAt, &l.LatestCommit,
		&l.FixedAuditID, &s.fixedAt, &l.FixedCommit,
		&l.Severity, &l.Category, &l.Title, &l.FilePath, &s.createdAt, &s.updatedAt,
		&l.RefNumber,
		&l.TargetKey, &l.FingerprintV2, &l.GitBranch, &l.Provenance, &l.QuoteHash,
		&l.EvidenceLineStart, &l.EvidenceLineEnd, &l.EvidenceFileHash,
		&l.SeenCount, &l.LastSeenAuditID, &l.MergedInto,
	}
}

// finish converts SQLite's text timestamps and derives the display ref.
func (s *sqliteLineageScanner) finish() *model.FindingLineage {
	l := &s.l
	l.FirstFoundAt, _ = time.Parse(time.RFC3339, s.firstFoundAt)
	l.CreatedAt, _ = time.Parse(time.RFC3339, s.createdAt)
	l.UpdatedAt, _ = time.Parse(time.RFC3339, s.updatedAt)
	if s.latestFoundAt.Valid && s.latestFoundAt.String != "" {
		t, _ := time.Parse(time.RFC3339, s.latestFoundAt.String)
		l.LatestFoundAt = &t
	}
	if s.fixedAt.Valid && s.fixedAt.String != "" {
		t, _ := time.Parse(time.RFC3339, s.fixedAt.String)
		l.FixedAt = &t
	}
	if l.RefNumber > 0 {
		l.Ref = l.FormatRef()
	}
	return l
}

func scanSQLiteLineage(row *sql.Row) (*model.FindingLineage, error) {
	var s sqliteLineageScanner
	err := row.Scan(s.targets()...)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan lineage: %w", err)
	}
	return s.finish(), nil
}

func scanSQLiteLineageRows(rows *sql.Rows) ([]model.FindingLineage, error) {
	var result []model.FindingLineage
	for rows.Next() {
		var s sqliteLineageScanner
		if err := rows.Scan(s.targets()...); err != nil {
			return nil, fmt.Errorf("scan lineage row: %w", err)
		}
		result = append(result, *s.finish())
	}
	return result, rows.Err()
}

// GetRecentlyFixedBySourcePath implements the bounded fixed-row re-check
// (feature 0091 §6.3): the `fixed` rows closed by the last `auditWindow`
// distinct fixing audits of this (source, agent).
//
// The window exists because the alternative bounds are both wrong. Re-checking
// EVERY fixed row grows without limit and re-sends thousands of rows to the
// agent on every scan; re-checking NONE is the S11 hole — a finding that comes
// back stays `fixed` forever, because the model was told to skip it and the
// backend has nothing else to notice it with.
func (r *SQLiteLineageRepo) GetRecentlyFixedBySourcePath(sourcePath, agentType string, auditWindow int) ([]model.FindingLineage, error) {
	if auditWindow <= 0 {
		return nil, nil
	}
	rows, err := r.db.Query(`
		SELECT `+sqliteLineageCols+`
		FROM finding_lineage
		WHERE source_path = ? AND agent_type = ? AND current_status = 'fixed'`+notMerged+`
		  AND COALESCE(fixed_audit_id,'') <> ''
		  AND fixed_audit_id IN (
			SELECT fixed_audit_id FROM finding_lineage
			WHERE source_path = ? AND agent_type = ? AND current_status = 'fixed'
			  AND COALESCE(fixed_audit_id,'') <> ''
			GROUP BY fixed_audit_id
			ORDER BY MAX(fixed_at) DESC
			LIMIT ?)`,
		sourcePath, agentType, sourcePath, agentType, auditWindow)
	if err != nil {
		return nil, fmt.Errorf("get recently fixed lineage: %w", err)
	}
	defer rows.Close()
	return scanSQLiteLineageRows(rows)
}

// RecentlyFixedByTarget is the target-keyed twin. Same window rule, same
// bound; only the partition changes. See the interface for why the path-keyed
// one could not serve it.
func (r *SQLiteLineageRepo) RecentlyFixedByTarget(targetKey, agentType string, auditWindow int) ([]model.FindingLineage, error) {
	if auditWindow <= 0 || targetKey == "" {
		return nil, nil
	}
	rows, err := r.db.Query(`
		SELECT `+sqliteLineageCols+`
		FROM finding_lineage
		WHERE target_key = ? AND agent_type = ? AND current_status = 'fixed'`+notMerged+`
		  AND COALESCE(fixed_audit_id,'') <> ''
		  AND fixed_audit_id IN (
			SELECT fixed_audit_id FROM finding_lineage
			WHERE target_key = ? AND agent_type = ? AND current_status = 'fixed'
			  AND COALESCE(fixed_audit_id,'') <> ''
			GROUP BY fixed_audit_id
			ORDER BY MAX(fixed_at) DESC
			LIMIT ?)`,
		targetKey, agentType, targetKey, agentType, auditWindow)
	if err != nil {
		return nil, fmt.Errorf("get recently fixed lineage by target: %w", err)
	}
	defer rows.Close()
	return scanSQLiteLineageRows(rows)
}

func (r *SQLiteLineageRepo) MarkUnconfirmed(id, auditID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := r.db.Exec(`
		UPDATE finding_lineage SET current_status = 'unconfirmed',
			last_seen_audit_id = ?, updated_at = ?
		WHERE id = ?`, nullIfEmpty(auditID), now, id)
	if err != nil {
		return fmt.Errorf("mark lineage unconfirmed: %w", err)
	}
	return nil
}

func (r *SQLiteLineageRepo) MarkSeen(id, auditID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := r.db.Exec(`
		UPDATE finding_lineage SET seen_count = COALESCE(seen_count, 1) + 1,
			last_seen_audit_id = ?, updated_at = ?
		WHERE id = ?`, nullIfEmpty(auditID), now, id)
	if err != nil {
		return fmt.Errorf("mark lineage seen: %w", err)
	}
	return nil
}

func (r *SQLiteLineageRepo) ApplyEvidence(id string, ev LineageEvidenceUpdate) error {
	now := time.Now().UTC().Format(time.RFC3339)
	// The window is written only when the caller says so; a re-anchor that is
	// not armed still records the file hash and (where earned) the sighting.
	sets := "evidence_file_hash = ?, last_seen_audit_id = ?, updated_at = ?"
	args := []interface{}{ev.FileHash, nullIfEmpty(ev.AuditID), now}
	if ev.IncrementSeen {
		sets += ", seen_count = COALESCE(seen_count, 1) + 1"
	}
	if ev.UpdateWindow {
		sets += ", evidence_line_start = ?, evidence_line_end = ?"
		args = append(args, ev.LineStart, ev.LineEnd)
	}
	args = append(args, id)
	if _, err := r.db.Exec(`UPDATE finding_lineage SET `+sets+` WHERE id = ?`, args...); err != nil {
		return fmt.Errorf("apply lineage evidence: %w", err)
	}
	return nil
}
