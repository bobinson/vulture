package repository

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/vulture/backend/internal/model"
)

type PostgresMemoryRepo struct {
	db *sql.DB
}

func NewPostgresMemoryRepo(db *sql.DB) *PostgresMemoryRepo {
	return &PostgresMemoryRepo{db: db}
}

func (r *PostgresMemoryRepo) StoreMemory(mem *model.AuditMemory) error {
	_, err := r.db.Exec(`
		INSERT INTO audit_memories (id, audit_id, agent_type, codebase_path, finding_type, title, content, severity, compliance_ref, category, keywords, tags, file_paths, remediation_status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (id) DO NOTHING`,
		mem.ID, mem.AuditID, mem.AgentType, mem.CodebasePath,
		mem.FindingType, mem.Title, mem.Content, string(mem.Severity),
		mem.ComplianceRef, mem.Category,
		pq.Array(mem.Keywords), pq.Array(mem.Tags), pq.Array(mem.FilePaths),
		mem.RemediationStatus, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("store memory: %w", err)
	}
	return nil
}

// StoreEmbedding writes the embedding vector for a memory.
func (r *PostgresMemoryRepo) StoreEmbedding(id string, embedding []float32) error {
	vecStr := float32SliceToVec(embedding)
	_, err := r.db.Exec(`UPDATE audit_memories SET embedding = $1 WHERE id = $2`, vecStr, id)
	if err != nil {
		return fmt.Errorf("store embedding: %w", err)
	}
	return nil
}

// SearchMemories searches by text or vector similarity.
// When embedding is non-nil, uses cosine distance via HNSW index.
func (r *PostgresMemoryRepo) SearchMemories(query string, embedding []float32, limit int) ([]model.AuditMemory, error) {
	if limit <= 0 {
		limit = 20
	}
	if len(embedding) > 0 {
		return r.searchByVector(embedding, limit)
	}
	return r.searchByText(query, limit)
}

func (r *PostgresMemoryRepo) searchByVector(embedding []float32, limit int) ([]model.AuditMemory, error) {
	vecStr := float32SliceToVec(embedding)
	dim := len(embedding)
	rows, err := r.db.Query(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, COALESCE(compliance_ref, ''), category,
		       keywords, tags, file_paths, remediation_status,
		       COALESCE(remediation_notes, ''), created_at,
		       1.0 - (embedding <=> $1::vector) AS sim
		FROM audit_memories
		WHERE embedding IS NOT NULL AND is_archived = false
		  AND vector_dims(embedding) = $3
		ORDER BY embedding <=> $1::vector
		LIMIT $2`,
		vecStr, limit, dim,
	)
	if err != nil {
		return nil, fmt.Errorf("vector search: %w", err)
	}
	defer rows.Close()
	return r.scanMemories(rows)
}

func (r *PostgresMemoryRepo) searchByText(query string, limit int) ([]model.AuditMemory, error) {
	rows, err := r.db.Query(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, COALESCE(compliance_ref, ''), category,
		       keywords, tags, file_paths, remediation_status,
		       COALESCE(remediation_notes, ''), created_at,
		       similarity(title || ' ' || content, $1) AS sim
		FROM audit_memories
		WHERE title || ' ' || content ILIKE '%' || $1 || '%'
		   OR $1 = ANY(keywords)
		ORDER BY sim DESC
		LIMIT $2`,
		query, limit,
	)
	if err != nil {
		return r.searchFallback(query, limit)
	}
	defer rows.Close()
	return r.scanMemories(rows)
}

func (r *PostgresMemoryRepo) searchFallback(query string, limit int) ([]model.AuditMemory, error) {
	rows, err := r.db.Query(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, COALESCE(compliance_ref, ''), category,
		       keywords, tags, file_paths, remediation_status,
		       COALESCE(remediation_notes, ''), created_at,
		       0.0 AS sim
		FROM audit_memories
		WHERE title ILIKE '%' || $1 || '%'
		   OR content ILIKE '%' || $1 || '%'
		   OR $1 = ANY(keywords)
		ORDER BY created_at DESC
		LIMIT $2`,
		query, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("search memories: %w", err)
	}
	defer rows.Close()
	return r.scanMemories(rows)
}

// FindSimilarByVector returns the top N similar memories by cosine distance,
// excluding the given memory ID.
func (r *PostgresMemoryRepo) FindSimilarByVector(excludeID string, embedding []float32, limit int) ([]model.AuditMemory, error) {
	vecStr := float32SliceToVec(embedding)
	dim := len(embedding)
	rows, err := r.db.Query(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, COALESCE(compliance_ref, ''), category,
		       keywords, tags, file_paths, remediation_status,
		       COALESCE(remediation_notes, ''), created_at,
		       1.0 - (embedding <=> $1::vector) AS sim
		FROM audit_memories
		WHERE embedding IS NOT NULL AND id != $2 AND is_archived = false
		  AND vector_dims(embedding) = $4
		ORDER BY embedding <=> $1::vector
		LIMIT $3`,
		vecStr, excludeID, limit, dim,
	)
	if err != nil {
		return nil, fmt.Errorf("find similar: %w", err)
	}
	defer rows.Close()
	return r.scanMemories(rows)
}

// StoreEdge creates a relationship between two memories.
func (r *PostgresMemoryRepo) StoreEdge(edge *model.MemoryEdge) error {
	_, err := r.db.Exec(`
		INSERT INTO memory_edges (source_id, target_id, relation_type, strength, bidirectional, edge_metadata, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT ON CONSTRAINT uq_edge_triple DO UPDATE SET strength = $4`,
		edge.SourceID, edge.TargetID, edge.RelationType, edge.Strength,
		edge.Bidirectional, "{}", edge.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("store edge: %w", err)
	}
	return nil
}

// GetEdges returns all edges connected to a memory (as source or target),
// enriched with the target memory's title and severity.
func (r *PostgresMemoryRepo) GetEdges(memoryID string) ([]model.MemoryEdge, error) {
	rows, err := r.db.Query(`
		SELECT e.id, e.source_id, e.target_id, e.relation_type, e.strength, e.bidirectional, e.created_by, e.created_at,
		       COALESCE(m.title, ''), COALESCE(m.severity, '')
		FROM memory_edges e
		LEFT JOIN audit_memories m ON m.id = CASE WHEN e.source_id = $1 THEN e.target_id ELSE e.source_id END
		WHERE e.source_id = $1 OR (e.target_id = $1 AND e.bidirectional = true)
		ORDER BY e.strength DESC`, memoryID)
	if err != nil {
		return nil, fmt.Errorf("get edges: %w", err)
	}
	defer rows.Close()

	var edges []model.MemoryEdge
	for rows.Next() {
		var e model.MemoryEdge
		if err := rows.Scan(&e.ID, &e.SourceID, &e.TargetID, &e.RelationType, &e.Strength, &e.Bidirectional, &e.CreatedBy, &e.CreatedAt, &e.TargetTitle, &e.TargetSeverity); err != nil {
			return nil, fmt.Errorf("scan edge: %w", err)
		}
		edges = append(edges, e)
	}
	return edges, rows.Err()
}

func (r *PostgresMemoryRepo) scanMemories(rows *sql.Rows) ([]model.AuditMemory, error) {
	var memories []model.AuditMemory
	for rows.Next() {
		var m model.AuditMemory
		err := rows.Scan(
			&m.ID, &m.AuditID, &m.AgentType, &m.CodebasePath,
			&m.FindingType, &m.Title, &m.Content,
			&m.Severity, &m.ComplianceRef, &m.Category,
			pq.Array(&m.Keywords), pq.Array(&m.Tags), pq.Array(&m.FilePaths),
			&m.RemediationStatus, &m.RemediationNotes, &m.CreatedAt,
			&m.Similarity,
		)
		if err != nil {
			return nil, fmt.Errorf("scan memory: %w", err)
		}
		memories = append(memories, m)
	}
	return memories, rows.Err()
}

func (r *PostgresMemoryRepo) GetMemory(id string) (*model.AuditMemory, error) {
	row := r.db.QueryRow(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, COALESCE(compliance_ref, ''), category,
		       keywords, tags, file_paths, remediation_status,
		       COALESCE(remediation_notes, ''), created_at
		FROM audit_memories WHERE id = $1`, id)
	var m model.AuditMemory
	err := row.Scan(
		&m.ID, &m.AuditID, &m.AgentType, &m.CodebasePath,
		&m.FindingType, &m.Title, &m.Content,
		&m.Severity, &m.ComplianceRef, &m.Category,
		pq.Array(&m.Keywords), pq.Array(&m.Tags), pq.Array(&m.FilePaths),
		&m.RemediationStatus, &m.RemediationNotes, &m.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get memory: %w", err)
	}
	return &m, nil
}

func (r *PostgresMemoryRepo) UpdateRemediation(id string, status string, notes string) error {
	_, err := r.db.Exec(`
		UPDATE audit_memories SET remediation_status = $1, remediation_notes = $2, updated_at = $3
		WHERE id = $4`,
		status, notes, time.Now().UTC(), id,
	)
	if err != nil {
		return fmt.Errorf("update remediation: %w", err)
	}
	return nil
}

func (r *PostgresMemoryRepo) ListByCodebasePath(path string, agentType string, limit int) ([]model.AuditMemory, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	if agentType != "" {
		rows, err = r.db.Query(`
			SELECT DISTINCT ON (title, finding_type)
			       id, audit_id, agent_type, codebase_path, finding_type, title, content,
			       severity, COALESCE(compliance_ref, ''), category,
			       keywords, tags, file_paths, remediation_status,
			       COALESCE(remediation_notes, ''), created_at,
			       0.0 AS sim
			FROM audit_memories
			WHERE codebase_path = $1 AND agent_type = $2 AND is_archived = false
			ORDER BY title, finding_type, created_at DESC
			LIMIT $3`,
			path, agentType, limit,
		)
	} else {
		rows, err = r.db.Query(`
			SELECT DISTINCT ON (title, finding_type)
			       id, audit_id, agent_type, codebase_path, finding_type, title, content,
			       severity, COALESCE(compliance_ref, ''), category,
			       keywords, tags, file_paths, remediation_status,
			       COALESCE(remediation_notes, ''), created_at,
			       0.0 AS sim
			FROM audit_memories
			WHERE codebase_path = $1 AND is_archived = false
			ORDER BY title, finding_type, created_at DESC
			LIMIT $2`,
			path, limit,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("list by codebase path: %w", err)
	}
	defer rows.Close()
	return r.scanMemories(rows)
}

func (r *PostgresMemoryRepo) ListMemoriesByAudit(auditID string) ([]model.AuditMemory, error) {
	rows, err := r.db.Query(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, COALESCE(compliance_ref, ''), category,
		       keywords, tags, file_paths, remediation_status,
		       COALESCE(remediation_notes, ''), created_at,
		       0.0 AS sim
		FROM audit_memories WHERE audit_id = $1
		ORDER BY severity, created_at DESC`,
		auditID,
	)
	if err != nil {
		return nil, fmt.Errorf("list memories: %w", err)
	}
	defer rows.Close()
	return r.scanMemories(rows)
}

// ListRecent returns the most recent memories across all audits.
func (r *PostgresMemoryRepo) ListRecent(limit int) ([]model.AuditMemory, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.db.Query(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, COALESCE(compliance_ref, ''), category,
		       keywords, tags, file_paths, remediation_status,
		       COALESCE(remediation_notes, ''), created_at,
		       0.0 AS sim
		FROM audit_memories
		WHERE is_archived = false
		ORDER BY created_at DESC
		LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list recent: %w", err)
	}
	defer rows.Close()
	return r.scanMemories(rows)
}

// float32SliceToVec converts a float32 slice to pgvector string format: [0.1,0.2,...]
func float32SliceToVec(v []float32) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, f := range v {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%g", f)
	}
	b.WriteByte(']')
	return b.String()
}
