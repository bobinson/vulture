package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vulture/backend/internal/model"
)

// SQLiteMemoryRepo implements MemoryRepository using SQLite.
// Text search uses LIKE; vector similarity falls back to keyword overlap.
type SQLiteMemoryRepo struct {
	db *sql.DB
}

func NewSQLiteMemoryRepo(db *sql.DB) (*SQLiteMemoryRepo, error) {
	if err := migrateMemory(db); err != nil {
		return nil, fmt.Errorf("migrate memory tables: %w", err)
	}
	return &SQLiteMemoryRepo{db: db}, nil
}

func migrateMemory(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_memories (
			id TEXT PRIMARY KEY,
			audit_id TEXT NOT NULL,
			agent_type TEXT NOT NULL,
			codebase_path TEXT NOT NULL,
			finding_type TEXT NOT NULL,
			title TEXT NOT NULL,
			content TEXT NOT NULL,
			severity TEXT NOT NULL,
			compliance_ref TEXT NOT NULL DEFAULT '',
			category TEXT NOT NULL DEFAULT '',
			keywords TEXT NOT NULL DEFAULT '[]',
			tags TEXT NOT NULL DEFAULT '[]',
			file_paths TEXT NOT NULL DEFAULT '[]',
			remediation_status TEXT NOT NULL DEFAULT 'open',
			remediation_notes TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE IF NOT EXISTS memory_embeddings (
			id TEXT PRIMARY KEY,
			embedding TEXT NOT NULL,
			FOREIGN KEY (id) REFERENCES audit_memories(id)
		);
		CREATE TABLE IF NOT EXISTS memory_edges (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source_id TEXT NOT NULL,
			target_id TEXT NOT NULL,
			relation_type TEXT NOT NULL,
			strength REAL NOT NULL DEFAULT 1.0,
			bidirectional INTEGER NOT NULL DEFAULT 0,
			created_by TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			FOREIGN KEY (source_id) REFERENCES audit_memories(id),
			FOREIGN KEY (target_id) REFERENCES audit_memories(id),
			UNIQUE(source_id, target_id, relation_type)
		);
	`)
	if err != nil {
		return err
	}
	// Index on keywords for non-leading-% queries and general query planning.
	// SQLite cannot use B-tree indexes for LIKE with leading %, but the index
	// benefits exact-match and prefix queries on this column.
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_memories_keywords ON audit_memories(keywords)`)
	return nil
}

func (r *SQLiteMemoryRepo) StoreMemory(mem *model.AuditMemory) error {
	keywordsJSON, err := json.Marshal(mem.Keywords)
	if err != nil {
		return fmt.Errorf("marshal keywords: %w", err)
	}
	tagsJSON, err := json.Marshal(mem.Tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}
	filePathsJSON, err := json.Marshal(mem.FilePaths)
	if err != nil {
		return fmt.Errorf("marshal file_paths: %w", err)
	}
	_, err = r.db.Exec(`
		INSERT INTO audit_memories (id, audit_id, agent_type, codebase_path, finding_type, title, content, severity, compliance_ref, category, keywords, tags, file_paths, remediation_status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO NOTHING`,
		mem.ID, mem.AuditID, mem.AgentType, mem.CodebasePath,
		mem.FindingType, mem.Title, mem.Content, string(mem.Severity),
		mem.ComplianceRef, mem.Category,
		string(keywordsJSON), string(tagsJSON), string(filePathsJSON),
		mem.RemediationStatus, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("store memory: %w", err)
	}
	return nil
}

func (r *SQLiteMemoryRepo) StoreEmbedding(id string, embedding []float32) error {
	data, err := json.Marshal(embedding)
	if err != nil {
		return fmt.Errorf("marshal embedding: %w", err)
	}
	_, err = r.db.Exec(`
		INSERT INTO memory_embeddings (id, embedding) VALUES (?, ?)
		ON CONFLICT (id) DO UPDATE SET embedding = excluded.embedding`,
		id, string(data),
	)
	if err != nil {
		return fmt.Errorf("store embedding: %w", err)
	}
	return nil
}

func (r *SQLiteMemoryRepo) SearchMemories(query string, _ []float32, limit int) ([]model.AuditMemory, error) {
	if limit <= 0 {
		limit = 20
	}
	pattern := "%" + query + "%"
	rows, err := r.db.Query(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, compliance_ref, category,
		       keywords, tags, file_paths, remediation_status,
		       remediation_notes, created_at,
		       0.0 AS sim
		FROM audit_memories
		WHERE title LIKE ? OR content LIKE ? OR keywords LIKE ?
		ORDER BY created_at DESC
		LIMIT ?`,
		pattern, pattern, pattern, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("search memories: %w", err)
	}
	defer rows.Close()
	return r.scanMemories(rows)
}

// HybridSearchMemories in SQLite falls back to text search since SQLite
// doesn't support pgvector operations. Same as SearchMemories.
func (r *SQLiteMemoryRepo) HybridSearchMemories(query string, _ []float32, limit int) ([]model.AuditMemory, error) {
	return r.SearchMemories(query, nil, limit)
}

func (r *SQLiteMemoryRepo) FindSimilarByVector(excludeID string, _ []float32, limit int) ([]model.AuditMemory, error) {
	if limit <= 0 {
		limit = 10
	}
	// Retrieve the source memory's keywords for overlap scoring.
	var keywordsJSON string
	err := r.db.QueryRow(`SELECT keywords FROM audit_memories WHERE id = ?`, excludeID).Scan(&keywordsJSON)
	if err != nil {
		return nil, fmt.Errorf("find similar lookup: %w", err)
	}
	var srcKeywords []string
	_ = json.Unmarshal([]byte(keywordsJSON), &srcKeywords)

	// Build LIKE clauses for keyword overlap.
	if len(srcKeywords) == 0 {
		return nil, nil
	}
	clauses := make([]string, 0, len(srcKeywords))
	args := make([]interface{}, 0, len(srcKeywords)+2)
	args = append(args, excludeID)
	for _, kw := range srcKeywords {
		clauses = append(clauses, "keywords LIKE ?")
		args = append(args, "%"+kw+"%")
	}
	args = append(args, limit)

	rows, err := r.db.Query(fmt.Sprintf(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, compliance_ref, category,
		       keywords, tags, file_paths, remediation_status,
		       remediation_notes, created_at,
		       0.0 AS sim
		FROM audit_memories
		WHERE id != ? AND (%s)
		ORDER BY created_at DESC
		LIMIT ?`, strings.Join(clauses, " OR ")), args...)
	if err != nil {
		return nil, fmt.Errorf("find similar: %w", err)
	}
	defer rows.Close()
	return r.scanMemories(rows)
}

func (r *SQLiteMemoryRepo) GetMemory(id string) (*model.AuditMemory, error) {
	row := r.db.QueryRow(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, compliance_ref, category,
		       keywords, tags, file_paths, remediation_status,
		       remediation_notes, created_at
		FROM audit_memories WHERE id = ?`, id)
	var m model.AuditMemory
	var keywordsJSON, tagsJSON, filePathsJSON, createdAt string
	err := row.Scan(
		&m.ID, &m.AuditID, &m.AgentType, &m.CodebasePath,
		&m.FindingType, &m.Title, &m.Content,
		&m.Severity, &m.ComplianceRef, &m.Category,
		&keywordsJSON, &tagsJSON, &filePathsJSON,
		&m.RemediationStatus, &m.RemediationNotes, &createdAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get memory: %w", err)
	}
	_ = json.Unmarshal([]byte(keywordsJSON), &m.Keywords)
	_ = json.Unmarshal([]byte(tagsJSON), &m.Tags)
	_ = json.Unmarshal([]byte(filePathsJSON), &m.FilePaths)
	m.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &m, nil
}

func (r *SQLiteMemoryRepo) UpdateRemediation(id string, status string, notes string) error {
	_, err := r.db.Exec(`
		UPDATE audit_memories SET remediation_status = ?, remediation_notes = ?, updated_at = ?
		WHERE id = ?`,
		status, notes, time.Now().UTC().Format(time.RFC3339), id,
	)
	if err != nil {
		return fmt.Errorf("update remediation: %w", err)
	}
	return nil
}

func (r *SQLiteMemoryRepo) ListMemoriesByAudit(auditID string) ([]model.AuditMemory, error) {
	rows, err := r.db.Query(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, compliance_ref, category,
		       keywords, tags, file_paths, remediation_status,
		       remediation_notes, created_at,
		       0.0 AS sim
		FROM audit_memories WHERE audit_id = ?
		ORDER BY severity, created_at DESC`,
		auditID,
	)
	if err != nil {
		return nil, fmt.Errorf("list memories by audit: %w", err)
	}
	defer rows.Close()
	return r.scanMemories(rows)
}

func (r *SQLiteMemoryRepo) ListByCodebasePath(path string, agentType string, limit int) ([]model.AuditMemory, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	if agentType != "" {
		rows, err = r.db.Query(`
			SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
			       severity, compliance_ref, category,
			       keywords, tags, file_paths, remediation_status,
			       remediation_notes, created_at,
			       0.0 AS sim
			FROM audit_memories
			WHERE codebase_path = ? AND agent_type = ?
			ORDER BY created_at DESC
			LIMIT ?`,
			path, agentType, limit,
		)
	} else {
		rows, err = r.db.Query(`
			SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
			       severity, compliance_ref, category,
			       keywords, tags, file_paths, remediation_status,
			       remediation_notes, created_at,
			       0.0 AS sim
			FROM audit_memories
			WHERE codebase_path = ?
			ORDER BY created_at DESC
			LIMIT ?`,
			path, limit,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("list by codebase path: %w", err)
	}
	defer rows.Close()
	return r.scanMemories(rows)
}

// ListByCodebasePathMulti fetches memories for multiple agent types in a single query.
func (r *SQLiteMemoryRepo) ListByCodebasePathMulti(path string, agentTypes []string, limit int) (map[string][]model.AuditMemory, error) {
	if limit <= 0 {
		limit = 50
	}
	if len(agentTypes) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(agentTypes))
	args := make([]interface{}, 0, len(agentTypes)+2)
	args = append(args, path)
	for i, at := range agentTypes {
		placeholders[i] = "?"
		args = append(args, at)
	}
	args = append(args, limit*len(agentTypes))
	rows, err := r.db.Query(fmt.Sprintf(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, compliance_ref, category,
		       keywords, tags, file_paths, remediation_status,
		       remediation_notes, created_at,
		       0.0 AS sim
		FROM audit_memories
		WHERE codebase_path = ? AND agent_type IN (%s)
		ORDER BY created_at DESC
		LIMIT ?`, strings.Join(placeholders, ",")), args...)
	if err != nil {
		return nil, fmt.Errorf("list by codebase path multi: %w", err)
	}
	defer rows.Close()
	memories, err := r.scanMemories(rows)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]model.AuditMemory, len(agentTypes))
	for _, m := range memories {
		if len(result[m.AgentType]) < limit {
			result[m.AgentType] = append(result[m.AgentType], m)
		}
	}
	return result, nil
}

// StoreBatch inserts multiple memories in a single transaction.
func (r *SQLiteMemoryRepo) StoreBatch(memories []*model.AuditMemory) error {
	if len(memories) == 0 {
		return nil
	}
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("begin batch: %w", err)
	}
	stmt, err := tx.Prepare(`
		INSERT INTO audit_memories (id, audit_id, agent_type, codebase_path, finding_type, title, content, severity, compliance_ref, category, keywords, tags, file_paths, remediation_status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO NOTHING`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("prepare batch: %w", err)
	}
	defer stmt.Close()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, mem := range memories {
		keywordsJSON, _ := json.Marshal(mem.Keywords)
		tagsJSON, _ := json.Marshal(mem.Tags)
		filePathsJSON, _ := json.Marshal(mem.FilePaths)
		_, err = stmt.Exec(
			mem.ID, mem.AuditID, mem.AgentType, mem.CodebasePath,
			mem.FindingType, mem.Title, mem.Content, string(mem.Severity),
			mem.ComplianceRef, mem.Category,
			string(keywordsJSON), string(tagsJSON), string(filePathsJSON),
			mem.RemediationStatus, now,
		)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("batch insert: %w", err)
		}
	}
	return tx.Commit()
}

func (r *SQLiteMemoryRepo) ListRecent(limit int) ([]model.AuditMemory, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.db.Query(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, compliance_ref, category,
		       keywords, tags, file_paths, remediation_status,
		       remediation_notes, created_at,
		       0.0 AS sim
		FROM audit_memories
		ORDER BY created_at DESC
		LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list recent: %w", err)
	}
	defer rows.Close()
	return r.scanMemories(rows)
}

func (r *SQLiteMemoryRepo) StoreEdge(edge *model.MemoryEdge) error {
	bidirectional := 0
	if edge.Bidirectional {
		bidirectional = 1
	}
	_, err := r.db.Exec(`
		INSERT INTO memory_edges (source_id, target_id, relation_type, strength, bidirectional, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (source_id, target_id, relation_type) DO UPDATE SET strength = excluded.strength`,
		edge.SourceID, edge.TargetID, edge.RelationType, edge.Strength,
		bidirectional, edge.CreatedBy, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("store edge: %w", err)
	}
	return nil
}

func (r *SQLiteMemoryRepo) GetEdges(memoryID string) ([]model.MemoryEdge, error) {
	rows, err := r.db.Query(`
		SELECT e.id, e.source_id, e.target_id, e.relation_type, e.strength, e.bidirectional, e.created_by, e.created_at,
		       COALESCE(m.title, ''), COALESCE(m.severity, '')
		FROM memory_edges e
		LEFT JOIN audit_memories m ON m.id = CASE WHEN e.source_id = ? THEN e.target_id ELSE e.source_id END
		WHERE e.source_id = ? OR (e.target_id = ? AND e.bidirectional = 1)
		ORDER BY e.strength DESC`, memoryID, memoryID, memoryID)
	if err != nil {
		return nil, fmt.Errorf("get edges: %w", err)
	}
	defer rows.Close()

	var edges []model.MemoryEdge
	for rows.Next() {
		var e model.MemoryEdge
		var bidirectional int
		var createdAt string
		if err := rows.Scan(&e.ID, &e.SourceID, &e.TargetID, &e.RelationType, &e.Strength, &bidirectional, &e.CreatedBy, &createdAt, &e.TargetTitle, &e.TargetSeverity); err != nil {
			return nil, fmt.Errorf("scan edge: %w", err)
		}
		e.Bidirectional = bidirectional != 0
		e.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		edges = append(edges, e)
	}
	return edges, rows.Err()
}

func (r *SQLiteMemoryRepo) scanMemories(rows *sql.Rows) ([]model.AuditMemory, error) {
	var memories []model.AuditMemory
	for rows.Next() {
		var m model.AuditMemory
		var keywordsJSON, tagsJSON, filePathsJSON, createdAt string
		err := rows.Scan(
			&m.ID, &m.AuditID, &m.AgentType, &m.CodebasePath,
			&m.FindingType, &m.Title, &m.Content,
			&m.Severity, &m.ComplianceRef, &m.Category,
			&keywordsJSON, &tagsJSON, &filePathsJSON,
			&m.RemediationStatus, &m.RemediationNotes, &createdAt,
			&m.Similarity,
		)
		if err != nil {
			return nil, fmt.Errorf("scan memory: %w", err)
		}
		_ = json.Unmarshal([]byte(keywordsJSON), &m.Keywords)
		_ = json.Unmarshal([]byte(tagsJSON), &m.Tags)
		_ = json.Unmarshal([]byte(filePathsJSON), &m.FilePaths)
		m.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		memories = append(memories, m)
	}
	return memories, rows.Err()
}
