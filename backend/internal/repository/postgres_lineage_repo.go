package repository

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/vulture/backend/internal/model"
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
			severity, category, title, file_path, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
		ON CONFLICT (fingerprint, source_path, agent_type) DO UPDATE SET
			latest_audit_id = $11, latest_found_at = $12, latest_commit = $13, updated_at = now()
		RETURNING id, ref_number`,
		l.ID, l.Fingerprint, l.SourcePath, l.AgentType, string(l.CurrentStatus),
		l.Notes, l.TicketURL, l.FirstAuditID, l.FirstFoundAt, l.FirstCommit,
		nullIfEmpty(l.LatestAuditID), l.LatestFoundAt, l.LatestCommit,
		nullIfEmpty(l.FixedAuditID), l.FixedAt, l.FixedCommit,
		l.Severity, l.Category, l.Title, l.FilePath, l.CreatedAt, l.UpdatedAt,
	).Scan(&l.ID, &l.RefNumber)
	if err != nil {
		return fmt.Errorf("upsert lineage: %w", err)
	}
	l.Ref = l.FormatRef()
	return nil
}

func (r *PostgresLineageRepo) GetLineage(id string) (*model.FindingLineage, error) {
	row := r.db.QueryRow(`
		SELECT id, fingerprint, source_path, agent_type, current_status,
			COALESCE(notes,''), COALESCE(ticket_url,''),
			first_audit_id, first_found_at, COALESCE(first_commit,''),
			COALESCE(latest_audit_id::text,''), latest_found_at, COALESCE(latest_commit,''),
			COALESCE(fixed_audit_id::text,''), fixed_at, COALESCE(fixed_commit,''),
			severity, category, title, file_path, created_at, updated_at,
			COALESCE(ref_number, 0)
		FROM finding_lineage WHERE id = $1`, id)
	return scanPostgresLineage(row)
}

func (r *PostgresLineageRepo) GetLineageByFingerprint(fingerprint, sourcePath, agentType string) (*model.FindingLineage, error) {
	row := r.db.QueryRow(`
		SELECT id, fingerprint, source_path, agent_type, current_status,
			COALESCE(notes,''), COALESCE(ticket_url,''),
			first_audit_id, first_found_at, COALESCE(first_commit,''),
			COALESCE(latest_audit_id::text,''), latest_found_at, COALESCE(latest_commit,''),
			COALESCE(fixed_audit_id::text,''), fixed_at, COALESCE(fixed_commit,''),
			severity, category, title, file_path, created_at, updated_at,
			COALESCE(ref_number, 0)
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
		SELECT id, fingerprint, source_path, agent_type, current_status,
			COALESCE(notes,''), COALESCE(ticket_url,''),
			first_audit_id, first_found_at, COALESCE(first_commit,''),
			COALESCE(latest_audit_id::text,''), latest_found_at, COALESCE(latest_commit,''),
			COALESCE(fixed_audit_id::text,''), fixed_at, COALESCE(fixed_commit,''),
			severity, category, title, file_path, created_at, updated_at,
			COALESCE(ref_number, 0)
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

func (r *PostgresLineageRepo) ListBySourcePath(sourcePath, status string, limit, offset int) ([]model.FindingLineage, error) {
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
				COALESCE(latest_audit_id::text,''), latest_found_at, COALESCE(latest_commit,''),
				COALESCE(fixed_audit_id::text,''), fixed_at, COALESCE(fixed_commit,''),
				severity, category, title, file_path, created_at, updated_at,
				COALESCE(ref_number, 0)
			FROM finding_lineage WHERE source_path = $1
			ORDER BY updated_at DESC LIMIT $2 OFFSET $3`, sourcePath, limit, offset)
	} else {
		rows, err = r.db.Query(`
			SELECT id, fingerprint, source_path, agent_type, current_status,
				COALESCE(notes,''), COALESCE(ticket_url,''),
				first_audit_id, first_found_at, COALESCE(first_commit,''),
				COALESCE(latest_audit_id::text,''), latest_found_at, COALESCE(latest_commit,''),
				COALESCE(fixed_audit_id::text,''), fixed_at, COALESCE(fixed_commit,''),
				severity, category, title, file_path, created_at, updated_at,
				COALESCE(ref_number, 0)
			FROM finding_lineage WHERE source_path = $1 AND current_status = $2
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
		SELECT fl.id, fl.fingerprint, fl.source_path, fl.agent_type, fl.current_status,
			COALESCE(fl.notes,''), COALESCE(fl.ticket_url,''),
			fl.first_audit_id, fl.first_found_at, COALESCE(fl.first_commit,''),
			COALESCE(fl.latest_audit_id::text,''), fl.latest_found_at, COALESCE(fl.latest_commit,''),
			COALESCE(fl.fixed_audit_id::text,''), fl.fixed_at, COALESCE(fl.fixed_commit,''),
			fl.severity, fl.category, fl.title, fl.file_path, fl.created_at, fl.updated_at,
			COALESCE(fl.ref_number, 0)
		FROM finding_lineage fl
		INNER JOIN findings f ON f.fingerprint = fl.fingerprint
			AND f.agent_type = fl.agent_type
		WHERE f.audit_id = $1
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

func (r *PostgresLineageRepo) GetOpenBySourcePath(sourcePath, agentType string) ([]model.FindingLineage, error) {
	rows, err := r.db.Query(`
		SELECT id, fingerprint, source_path, agent_type, current_status,
			COALESCE(notes,''), COALESCE(ticket_url,''),
			first_audit_id, first_found_at, COALESCE(first_commit,''),
			COALESCE(latest_audit_id::text,''), latest_found_at, COALESCE(latest_commit,''),
			COALESCE(fixed_audit_id::text,''), fixed_at, COALESCE(fixed_commit,''),
			severity, category, title, file_path, created_at, updated_at,
			COALESCE(ref_number, 0)
		FROM finding_lineage
		WHERE source_path = $1 AND agent_type = $2 AND current_status IN ('open','in_progress')`, sourcePath, agentType)
	if err != nil {
		return nil, fmt.Errorf("get open lineage: %w", err)
	}
	defer rows.Close()
	return scanPostgresLineageRows(rows)
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

func scanPostgresLineage(row *sql.Row) (*model.FindingLineage, error) {
	var l model.FindingLineage
	var latestFoundAt, fixedAt sql.NullTime
	err := row.Scan(
		&l.ID, &l.Fingerprint, &l.SourcePath, &l.AgentType, &l.CurrentStatus,
		&l.Notes, &l.TicketURL,
		&l.FirstAuditID, &l.FirstFoundAt, &l.FirstCommit,
		&l.LatestAuditID, &latestFoundAt, &l.LatestCommit,
		&l.FixedAuditID, &fixedAt, &l.FixedCommit,
		&l.Severity, &l.Category, &l.Title, &l.FilePath, &l.CreatedAt, &l.UpdatedAt,
		&l.RefNumber,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan lineage: %w", err)
	}
	if latestFoundAt.Valid {
		l.LatestFoundAt = &latestFoundAt.Time
	}
	if fixedAt.Valid {
		l.FixedAt = &fixedAt.Time
	}
	if l.RefNumber > 0 {
		l.Ref = l.FormatRef()
	}
	return &l, nil
}

func scanPostgresLineageRows(rows *sql.Rows) ([]model.FindingLineage, error) {
	var result []model.FindingLineage
	for rows.Next() {
		var l model.FindingLineage
		var latestFoundAt, fixedAt sql.NullTime
		if err := rows.Scan(
			&l.ID, &l.Fingerprint, &l.SourcePath, &l.AgentType, &l.CurrentStatus,
			&l.Notes, &l.TicketURL,
			&l.FirstAuditID, &l.FirstFoundAt, &l.FirstCommit,
			&l.LatestAuditID, &latestFoundAt, &l.LatestCommit,
			&l.FixedAuditID, &fixedAt, &l.FixedCommit,
			&l.Severity, &l.Category, &l.Title, &l.FilePath, &l.CreatedAt, &l.UpdatedAt,
			&l.RefNumber,
		); err != nil {
			return nil, fmt.Errorf("scan lineage row: %w", err)
		}
		if latestFoundAt.Valid {
			l.LatestFoundAt = &latestFoundAt.Time
		}
		if fixedAt.Valid {
			l.FixedAt = &fixedAt.Time
		}
		if l.RefNumber > 0 {
			l.Ref = l.FormatRef()
		}
		result = append(result, l)
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
