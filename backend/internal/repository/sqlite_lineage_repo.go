package repository

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/vulture/backend/internal/model"
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
		// Update existing
		var latestFoundAt string
		if l.LatestFoundAt != nil {
			latestFoundAt = l.LatestFoundAt.Format(time.RFC3339)
		}
		_, err = r.db.Exec(`
			UPDATE finding_lineage SET latest_audit_id = ?, latest_found_at = ?, latest_commit = ?, updated_at = ?
			WHERE id = ?`,
			l.LatestAuditID, latestFoundAt, l.LatestCommit, now.Format(time.RFC3339), existing.ID)
		if err != nil {
			return fmt.Errorf("update lineage: %w", err)
		}
		l.ID = existing.ID
		return nil
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
	defer tx.Rollback()

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
			ref_number
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		l.ID, l.Fingerprint, l.SourcePath, l.AgentType, string(l.CurrentStatus),
		l.Notes, l.TicketURL, l.FirstAuditID, l.FirstFoundAt.Format(time.RFC3339), l.FirstCommit,
		l.LatestAuditID, latestFoundAt, l.LatestCommit,
		l.FixedAuditID, fixedAt, l.FixedCommit,
		l.Severity, l.Category, l.Title, l.FilePath,
		l.CreatedAt.Format(time.RFC3339), l.UpdatedAt.Format(time.RFC3339),
		l.RefNumber,
	)
	if err != nil {
		return fmt.Errorf("insert lineage: %w", err)
	}
	return tx.Commit()
}

func (r *SQLiteLineageRepo) GetLineage(id string) (*model.FindingLineage, error) {
	row := r.db.QueryRow(`
		SELECT id, fingerprint, source_path, agent_type, current_status,
			COALESCE(notes,''), COALESCE(ticket_url,''),
			first_audit_id, first_found_at, COALESCE(first_commit,''),
			COALESCE(latest_audit_id,''), latest_found_at, COALESCE(latest_commit,''),
			COALESCE(fixed_audit_id,''), fixed_at, COALESCE(fixed_commit,''),
			severity, category, title, file_path, created_at, updated_at,
			COALESCE(ref_number, 0)
		FROM finding_lineage WHERE id = ?`, id)
	return scanSQLiteLineage(row)
}

func (r *SQLiteLineageRepo) GetLineageByFingerprint(fingerprint, sourcePath, agentType string) (*model.FindingLineage, error) {
	row := r.db.QueryRow(`
		SELECT id, fingerprint, source_path, agent_type, current_status,
			COALESCE(notes,''), COALESCE(ticket_url,''),
			first_audit_id, first_found_at, COALESCE(first_commit,''),
			COALESCE(latest_audit_id,''), latest_found_at, COALESCE(latest_commit,''),
			COALESCE(fixed_audit_id,''), fixed_at, COALESCE(fixed_commit,''),
			severity, category, title, file_path, created_at, updated_at,
			COALESCE(ref_number, 0)
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
		SELECT id, fingerprint, source_path, agent_type, current_status,
			COALESCE(notes,''), COALESCE(ticket_url,''),
			first_audit_id, first_found_at, COALESCE(first_commit,''),
			COALESCE(latest_audit_id,''), latest_found_at, COALESCE(latest_commit,''),
			COALESCE(fixed_audit_id,''), fixed_at, COALESCE(fixed_commit,''),
			severity, category, title, file_path, created_at, updated_at,
			COALESCE(ref_number, 0)
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

func (r *SQLiteLineageRepo) ListBySourcePath(sourcePath, status string, limit, offset int) ([]model.FindingLineage, error) {
	if limit <= 0 {
		limit = 20
	}
	var rows *sql.Rows
	var err error
	if status == "" {
		rows, err = r.db.Query(`
			SELECT id, fingerprint, source_path, agent_type, current_status,
				COALESCE(notes,''), COALESCE(ticket_url,''),
				first_audit_id, first_found_at, COALESCE(first_commit,''),
				COALESCE(latest_audit_id,''), latest_found_at, COALESCE(latest_commit,''),
				COALESCE(fixed_audit_id,''), fixed_at, COALESCE(fixed_commit,''),
				severity, category, title, file_path, created_at, updated_at,
				COALESCE(ref_number, 0)
			FROM finding_lineage WHERE source_path = ?
			ORDER BY updated_at DESC LIMIT ? OFFSET ?`, sourcePath, limit, offset)
	} else {
		rows, err = r.db.Query(`
			SELECT id, fingerprint, source_path, agent_type, current_status,
				COALESCE(notes,''), COALESCE(ticket_url,''),
				first_audit_id, first_found_at, COALESCE(first_commit,''),
				COALESCE(latest_audit_id,''), latest_found_at, COALESCE(latest_commit,''),
				COALESCE(fixed_audit_id,''), fixed_at, COALESCE(fixed_commit,''),
				severity, category, title, file_path, created_at, updated_at,
				COALESCE(ref_number, 0)
			FROM finding_lineage WHERE source_path = ? AND current_status = ?
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
		SELECT fl.id, fl.fingerprint, fl.source_path, fl.agent_type, fl.current_status,
			COALESCE(fl.notes,''), COALESCE(fl.ticket_url,''),
			fl.first_audit_id, fl.first_found_at, COALESCE(fl.first_commit,''),
			COALESCE(fl.latest_audit_id,''), fl.latest_found_at, COALESCE(fl.latest_commit,''),
			COALESCE(fl.fixed_audit_id,''), fl.fixed_at, COALESCE(fl.fixed_commit,''),
			fl.severity, fl.category, fl.title, fl.file_path, fl.created_at, fl.updated_at,
			COALESCE(fl.ref_number, 0)
		FROM finding_lineage fl
		INNER JOIN findings f ON f.fingerprint = fl.fingerprint
			AND f.agent_type = fl.agent_type
		WHERE f.audit_id = ?
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

func (r *SQLiteLineageRepo) GetOpenBySourcePath(sourcePath, agentType string) ([]model.FindingLineage, error) {
	rows, err := r.db.Query(`
		SELECT id, fingerprint, source_path, agent_type, current_status,
			COALESCE(notes,''), COALESCE(ticket_url,''),
			first_audit_id, first_found_at, COALESCE(first_commit,''),
			COALESCE(latest_audit_id,''), latest_found_at, COALESCE(latest_commit,''),
			COALESCE(fixed_audit_id,''), fixed_at, COALESCE(fixed_commit,''),
			severity, category, title, file_path, created_at, updated_at,
			COALESCE(ref_number, 0)
		FROM finding_lineage
		WHERE source_path = ? AND agent_type = ? AND current_status IN ('open','in_progress')`, sourcePath, agentType)
	if err != nil {
		return nil, fmt.Errorf("get open lineage: %w", err)
	}
	defer rows.Close()
	return scanSQLiteLineageRows(rows)
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
		e.OldStatus, e.NewStatus, e.Notes, e.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("add lineage event: %w", err)
	}
	return nil
}

func (r *SQLiteLineageRepo) GetEvents(lineageID string) ([]model.LineageEvent, error) {
	rows, err := r.db.Query(`
		SELECT id, lineage_id, event_type, COALESCE(audit_id,''), COALESCE(git_commit,''),
			COALESCE(git_branch,''), COALESCE(old_status,''), COALESCE(new_status,''),
			COALESCE(notes,''), created_at
		FROM lineage_events WHERE lineage_id = ?
		ORDER BY created_at ASC`, lineageID)
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

func scanSQLiteLineage(row *sql.Row) (*model.FindingLineage, error) {
	var l model.FindingLineage
	var firstFoundAt, createdAt, updatedAt string
	var latestFoundAt, fixedAt sql.NullString
	err := row.Scan(
		&l.ID, &l.Fingerprint, &l.SourcePath, &l.AgentType, &l.CurrentStatus,
		&l.Notes, &l.TicketURL,
		&l.FirstAuditID, &firstFoundAt, &l.FirstCommit,
		&l.LatestAuditID, &latestFoundAt, &l.LatestCommit,
		&l.FixedAuditID, &fixedAt, &l.FixedCommit,
		&l.Severity, &l.Category, &l.Title, &l.FilePath, &createdAt, &updatedAt,
		&l.RefNumber,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan lineage: %w", err)
	}
	l.FirstFoundAt, _ = time.Parse(time.RFC3339, firstFoundAt)
	l.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	l.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	if latestFoundAt.Valid && latestFoundAt.String != "" {
		t, _ := time.Parse(time.RFC3339, latestFoundAt.String)
		l.LatestFoundAt = &t
	}
	if fixedAt.Valid && fixedAt.String != "" {
		t, _ := time.Parse(time.RFC3339, fixedAt.String)
		l.FixedAt = &t
	}
	if l.RefNumber > 0 {
		l.Ref = l.FormatRef()
	}
	return &l, nil
}

func scanSQLiteLineageRows(rows *sql.Rows) ([]model.FindingLineage, error) {
	var result []model.FindingLineage
	for rows.Next() {
		var l model.FindingLineage
		var firstFoundAt, createdAt, updatedAt string
		var latestFoundAt, fixedAt sql.NullString
		if err := rows.Scan(
			&l.ID, &l.Fingerprint, &l.SourcePath, &l.AgentType, &l.CurrentStatus,
			&l.Notes, &l.TicketURL,
			&l.FirstAuditID, &firstFoundAt, &l.FirstCommit,
			&l.LatestAuditID, &latestFoundAt, &l.LatestCommit,
			&l.FixedAuditID, &fixedAt, &l.FixedCommit,
			&l.Severity, &l.Category, &l.Title, &l.FilePath, &createdAt, &updatedAt,
			&l.RefNumber,
		); err != nil {
			return nil, fmt.Errorf("scan lineage row: %w", err)
		}
		l.FirstFoundAt, _ = time.Parse(time.RFC3339, firstFoundAt)
		l.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		l.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		if latestFoundAt.Valid && latestFoundAt.String != "" {
			t, _ := time.Parse(time.RFC3339, latestFoundAt.String)
			l.LatestFoundAt = &t
		}
		if fixedAt.Valid && fixedAt.String != "" {
			t, _ := time.Parse(time.RFC3339, fixedAt.String)
			l.FixedAt = &t
		}
		if l.RefNumber > 0 {
			l.Ref = l.FormatRef()
		}
		result = append(result, l)
	}
	return result, rows.Err()
}
