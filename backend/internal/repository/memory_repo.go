package repository

import (
	"database/sql"
	"fmt"
	"log"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/vulture/backend/internal/model"
)

// Hybrid search weights: 70% vector similarity, 30% text relevance.
const (
	vectorWeight = 0.7
	textWeight   = 0.3
)

// Temporal decay half-life in days. Scores halve every 90 days.
const decayHalfLifeDays = 90.0

// MMR diversity: lambda controls relevance vs diversity tradeoff (1.0 = pure relevance).
const mmrLambda = 0.8

type PostgresMemoryRepo struct {
	db *sql.DB
}

func NewPostgresMemoryRepo(db *sql.DB) *PostgresMemoryRepo {
	return &PostgresMemoryRepo{db: db}
}

func (r *PostgresMemoryRepo) StoreMemory(mem *model.AuditMemory) error {
	keywords := coalesceSlice(mem.Keywords)
	tags := coalesceSlice(mem.Tags)
	filePaths := coalesceSlice(mem.FilePaths)
	_, err := r.db.Exec(`
		INSERT INTO audit_memories (id, audit_id, agent_type, codebase_path, finding_type, title, content, severity, fingerprint, compliance_ref, category, keywords, tags, file_paths, remediation_status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (id) DO NOTHING`,
		mem.ID, mem.AuditID, mem.AgentType, mem.CodebasePath,
		mem.FindingType, mem.Title, mem.Content, string(mem.Severity),
		sql.NullString{String: mem.Fingerprint, Valid: mem.Fingerprint != ""},
		mem.ComplianceRef, mem.Category,
		pq.Array(keywords), pq.Array(tags), pq.Array(filePaths),
		mem.RemediationStatus, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("store memory: %w", err)
	}
	return nil
}

func coalesceSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
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
	// Use the dim-cast form `(embedding::vector(N)) <=> ($1::vector(N))` so
	// the partial HNSW index added in migration 015 is eligible. The dim
	// is interpolated as an integer literal — never user input — so this
	// is safe wrt SQL injection.
	q := fmt.Sprintf(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, COALESCE(compliance_ref, ''), category,
		       keywords, tags, file_paths, remediation_status,
		       COALESCE(remediation_notes, ''), created_at,
		       1.0 - ((embedding::vector(%[1]d)) <=> ($1::vector(%[1]d))) AS sim,
		       confidence_score, embedding::text
		FROM audit_memories
		WHERE embedding IS NOT NULL AND is_archived = false
		  AND vector_dims(embedding) = $3
		ORDER BY (embedding::vector(%[1]d)) <=> ($1::vector(%[1]d))
		LIMIT $2`, dim)
	rows, err := r.db.Query(q, vecStr, limit, dim)
	if err != nil {
		return nil, fmt.Errorf("vector search: %w", err)
	}
	defer rows.Close()
	return r.scanMemoriesWithEmbedding(rows)
}

func (r *PostgresMemoryRepo) searchByText(query string, limit int) ([]model.AuditMemory, error) {
	// Use ts_rank with plainto_tsquery for BM25-like relevance scoring.
	// Falls back to ILIKE if full-text search returns no results.
	rows, err := r.db.Query(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, COALESCE(compliance_ref, ''), category,
		       keywords, tags, file_paths, remediation_status,
		       COALESCE(remediation_notes, ''), created_at,
		       ts_rank(to_tsvector('english', title || ' ' || content),
		               plainto_tsquery('english', $1)) AS sim
		FROM audit_memories
		WHERE to_tsvector('english', title || ' ' || content) @@ plainto_tsquery('english', $1)
		   OR $1 = ANY(keywords)
		ORDER BY sim DESC
		LIMIT $2`,
		query, limit,
	)
	if err != nil {
		log.Printf("[memory] ts_rank query failed, falling back to ILIKE: %v", err)
		return r.searchFallback(query, limit)
	}
	defer rows.Close()
	results, err := r.scanMemories(rows)
	if err != nil {
		return nil, err
	}
	// If ts_rank returns nothing, close rows first then fall through to ILIKE
	if len(results) == 0 {
		rows.Close()
		return r.searchFallback(query, limit)
	}
	return results, nil
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

// HybridSearchMemories combines vector similarity (0.7 weight) and text
// relevance via ts_rank (0.3 weight) with temporal decay and MMR diversity.
// Falls back to plain text search when embedding is nil.
func (r *PostgresMemoryRepo) HybridSearchMemories(query string, embedding []float32, limit int) ([]model.AuditMemory, error) {
	if limit <= 0 {
		limit = 20
	}
	if len(embedding) == 0 {
		return r.searchByText(query, limit)
	}
	// Fetch more candidates from each source for better fusion.
	fetchLimit := limit * 3

	vectorResults, vecErr := r.searchByVector(embedding, fetchLimit)
	textResults, txtErr := r.searchByText(query, fetchLimit)

	// If one fails, return the other.
	if vecErr != nil && txtErr != nil {
		return r.searchFallback(query, limit)
	}
	if vecErr != nil {
		return applyDecayAndMMR(textResults, limit), nil
	}
	if txtErr != nil {
		return applyDecayAndMMR(vectorResults, limit), nil
	}

	merged := weightedFusion(vectorResults, textResults)
	return applyDecayAndMMR(merged, limit), nil
}

// weightedFusion combines vector and text results with configurable weights.
// Vector results contribute vectorWeight (0.7) and text results contribute
// textWeight (0.3). Scores are normalized within each list before weighting.
func weightedFusion(vectorList, textList []model.AuditMemory) []model.AuditMemory {
	type scored struct {
		mem   model.AuditMemory
		score float64
	}
	byID := map[string]*scored{}

	// Normalize and weight vector results
	vecMax := maxSimilarity(vectorList)
	for _, m := range vectorList {
		norm := 0.0
		if vecMax > 0 {
			norm = m.Similarity / vecMax
		}
		s := norm * vectorWeight
		if existing, ok := byID[m.ID]; ok {
			existing.score += s
		} else {
			byID[m.ID] = &scored{mem: m, score: s}
		}
	}

	// Normalize and weight text results
	txtMax := maxSimilarity(textList)
	for _, m := range textList {
		norm := 0.0
		if txtMax > 0 {
			norm = m.Similarity / txtMax
		}
		s := norm * textWeight
		if existing, ok := byID[m.ID]; ok {
			existing.score += s
		} else {
			byID[m.ID] = &scored{mem: m, score: s}
		}
	}

	// Collect and sort by weighted score descending
	items := make([]*scored, 0, len(byID))
	for _, s := range byID {
		items = append(items, s)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].score > items[j].score
	})

	result := make([]model.AuditMemory, 0, len(items))
	for _, s := range items {
		s.mem.Similarity = s.score
		result = append(result, s.mem)
	}
	return result
}

// maxSimilarity returns the maximum similarity score in a list.
func maxSimilarity(list []model.AuditMemory) float64 {
	m := 0.0
	for _, item := range list {
		if item.Similarity > m {
			m = item.Similarity
		}
	}
	return m
}

// temporalDecay returns a decay factor in [0, 1] based on age.
// Uses exponential decay with half-life of decayHalfLifeDays.
func temporalDecay(createdAt time.Time) float64 {
	if createdAt.IsZero() {
		return 0.5 // unknown age, neutral
	}
	ageDays := time.Since(createdAt).Hours() / 24.0
	if ageDays < 0 {
		ageDays = 0
	}
	return math.Exp(-0.693 * ageDays / decayHalfLifeDays)
}

// applyDecayAndMMR applies temporal decay and confidence boosting to scores,
// then filters for diversity using Maximal Marginal Relevance (MMR) with
// embedding-space cosine similarity when vectors are available.
func applyDecayAndMMR(items []model.AuditMemory, limit int) []model.AuditMemory {
	if len(items) == 0 {
		return items
	}
	// Apply temporal decay and confidence boost
	for i := range items {
		decay := temporalDecay(items[i].CreatedAt)
		items[i].Similarity = confidenceBoost(items[i].Similarity*decay, items[i].ConfidenceScore)
	}

	// Re-sort after decay + confidence
	sort.Slice(items, func(i, j int) bool {
		return items[i].Similarity > items[j].Similarity
	})

	// MMR diversity filtering using embedding-space cosine similarity
	return mmrFilter(items, limit)
}

// mmrFilter implements Maximal Marginal Relevance for diversity.
// It greedily selects items, penalizing those too similar to already-selected ones.
// Similarity between items is estimated by title/category overlap.
func mmrFilter(candidates []model.AuditMemory, limit int) []model.AuditMemory {
	if len(candidates) <= limit {
		return candidates
	}
	selected := make([]model.AuditMemory, 0, limit)
	used := make(map[int]bool, limit)

	for len(selected) < limit {
		bestIdx := -1
		bestMMR := -1.0

		for i, c := range candidates {
			if used[i] {
				continue
			}
			relevance := c.Similarity
			maxSim := maxSelectedSimilarity(c, selected)
			mmrScore := mmrLambda*relevance - (1.0-mmrLambda)*maxSim
			if mmrScore > bestMMR {
				bestMMR = mmrScore
				bestIdx = i
			}
		}
		if bestIdx < 0 {
			break
		}
		used[bestIdx] = true
		selected = append(selected, candidates[bestIdx])
	}
	return selected
}

// maxSelectedSimilarity estimates how similar a candidate is to already-selected items.
// Uses embedding-space cosine similarity when embeddings are available,
// falls back to Jaccard coefficient on title+category tokens.
func maxSelectedSimilarity(candidate model.AuditMemory, selected []model.AuditMemory) float64 {
	maxSim := 0.0
	for _, s := range selected {
		sim := embeddingOrJaccardSimilarity(candidate, s)
		if sim > maxSim {
			maxSim = sim
		}
	}
	return maxSim
}

// embeddingOrJaccardSimilarity uses cosine similarity on embeddings when both
// memories have them, otherwise falls back to Jaccard on title+category.
func embeddingOrJaccardSimilarity(a, b model.AuditMemory) float64 {
	if len(a.Embedding) > 0 && len(b.Embedding) > 0 && len(a.Embedding) == len(b.Embedding) {
		return cosineSimilarity(a.Embedding, b.Embedding)
	}
	return jaccardSimilarity(a, b)
}

// cosineSimilarity computes cosine similarity between two float32 vectors.
func cosineSimilarity(a, b []float32) float64 {
	var dot, normA, normB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}
	denom := math.Sqrt(normA) * math.Sqrt(normB)
	if denom == 0 {
		return 0.0
	}
	return dot / denom
}

// jaccardSimilarity estimates similarity between two memories using
// keyword overlap (Jaccard coefficient on title words + category).
func jaccardSimilarity(a, b model.AuditMemory) float64 {
	aWords := tokenize(a.Title + " " + a.Category)
	bWords := tokenize(b.Title + " " + b.Category)
	if len(aWords) == 0 && len(bWords) == 0 {
		return 0.0
	}
	intersection := 0
	for w := range aWords {
		if bWords[w] {
			intersection++
		}
	}
	union := len(aWords) + len(bWords) - intersection
	if union == 0 {
		return 0.0
	}
	return float64(intersection) / float64(union)
}

// confidenceBoost adjusts a memory's similarity score by its confidence.
// Higher confidence findings are boosted; low confidence findings are dampened.
// Formula: score * (0.7 + 0.3 * confidence) — maps confidence [0,1] to boost [0.7, 1.0].
func confidenceBoost(score, confidence float64) float64 {
	return score * (0.7 + 0.3*confidence)
}

// tokenize splits text into lowercase word tokens.
func tokenize(text string) map[string]bool {
	words := strings.Fields(strings.ToLower(text))
	set := make(map[string]bool, len(words))
	for _, w := range words {
		w = strings.Trim(w, ".,;:!?()[]{}\"'")
		if len(w) >= 2 {
			set[w] = true
		}
	}
	return set
}

// FindSimilarByVector returns the top N similar memories by cosine distance,
// excluding the given memory ID.
func (r *PostgresMemoryRepo) FindSimilarByVector(excludeID string, embedding []float32, limit int) ([]model.AuditMemory, error) {
	vecStr := float32SliceToVec(embedding)
	dim := len(embedding)
	// See searchByVector for why the dim is fmt-interpolated.
	q := fmt.Sprintf(`
		SELECT id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, COALESCE(compliance_ref, ''), category,
		       keywords, tags, file_paths, remediation_status,
		       COALESCE(remediation_notes, ''), created_at,
		       1.0 - ((embedding::vector(%[1]d)) <=> ($1::vector(%[1]d))) AS sim
		FROM audit_memories
		WHERE embedding IS NOT NULL AND id != $2 AND is_archived = false
		  AND vector_dims(embedding) = $4
		ORDER BY (embedding::vector(%[1]d)) <=> ($1::vector(%[1]d))
		LIMIT $3`, dim)
	rows, err := r.db.Query(q, vecStr, excludeID, limit, dim)
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

// scanMemoriesWithEmbedding scans rows that include confidence_score and embedding text.
func (r *PostgresMemoryRepo) scanMemoriesWithEmbedding(rows *sql.Rows) ([]model.AuditMemory, error) {
	var memories []model.AuditMemory
	for rows.Next() {
		var m model.AuditMemory
		var embText sql.NullString
		err := rows.Scan(
			&m.ID, &m.AuditID, &m.AgentType, &m.CodebasePath,
			&m.FindingType, &m.Title, &m.Content,
			&m.Severity, &m.ComplianceRef, &m.Category,
			pq.Array(&m.Keywords), pq.Array(&m.Tags), pq.Array(&m.FilePaths),
			&m.RemediationStatus, &m.RemediationNotes, &m.CreatedAt,
			&m.Similarity, &m.ConfidenceScore, &embText,
		)
		if err != nil {
			return nil, fmt.Errorf("scan memory with embedding: %w", err)
		}
		if embText.Valid {
			m.Embedding = vecTextToFloat32Slice(embText.String)
		}
		memories = append(memories, m)
	}
	return memories, rows.Err()
}

// vecTextToFloat32Slice parses pgvector text format "[0.1,0.2,...]" to []float32.
func vecTextToFloat32Slice(text string) []float32 {
	text = strings.Trim(text, "[]")
	if text == "" {
		return nil
	}
	parts := strings.Split(text, ",")
	result := make([]float32, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if f, err := strconv.ParseFloat(p, 64); err == nil {
			result = append(result, float32(f))
		}
	}
	return result
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
	// Determine confidence delta based on remediation action.
	var confidenceDelta float64
	switch status {
	case "resolved", "fixed":
		confidenceDelta = 0.1 // confirmed finding → boost confidence
	case "false_positive":
		confidenceDelta = -0.2 // false positive → reduce confidence
	}

	_, err := r.db.Exec(`
		UPDATE audit_memories
		SET remediation_status = $1,
		    remediation_notes = $2,
		    updated_at = $3,
		    confidence_score = LEAST(1.0, GREATEST(0.0, confidence_score + $5))
		WHERE id = $4`,
		status, notes, time.Now().UTC(), id, confidenceDelta,
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

// ListByCodebasePathMulti fetches memories for multiple agent types in a single query.
func (r *PostgresMemoryRepo) ListByCodebasePathMulti(path string, agentTypes []string, limit int) (map[string][]model.AuditMemory, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.Query(`
		SELECT DISTINCT ON (title, finding_type)
		       id, audit_id, agent_type, codebase_path, finding_type, title, content,
		       severity, COALESCE(compliance_ref, ''), category,
		       keywords, tags, file_paths, remediation_status,
		       COALESCE(remediation_notes, ''), created_at,
		       0.0 AS sim
		FROM audit_memories
		WHERE codebase_path = $1 AND agent_type = ANY($2) AND is_archived = false
		ORDER BY title, finding_type, created_at DESC
		LIMIT $3`,
		path, pq.Array(agentTypes), limit*len(agentTypes),
	)
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
func (r *PostgresMemoryRepo) StoreBatch(memories []*model.AuditMemory) error {
	if len(memories) == 0 {
		return nil
	}
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("begin batch: %w", err)
	}
	stmt, err := tx.Prepare(`
		INSERT INTO audit_memories (id, audit_id, agent_type, codebase_path, finding_type, title, content, severity, fingerprint, compliance_ref, category, keywords, tags, file_paths, remediation_status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (id) DO NOTHING`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("prepare batch: %w", err)
	}
	defer stmt.Close()
	now := time.Now().UTC()
	for _, mem := range memories {
		keywords := coalesceSlice(mem.Keywords)
		tags := coalesceSlice(mem.Tags)
		filePaths := coalesceSlice(mem.FilePaths)
		_, err = stmt.Exec(
			mem.ID, mem.AuditID, mem.AgentType, mem.CodebasePath,
			mem.FindingType, mem.Title, mem.Content, string(mem.Severity),
			sql.NullString{String: mem.Fingerprint, Valid: mem.Fingerprint != ""},
			mem.ComplianceRef, mem.Category,
			pq.Array(keywords), pq.Array(tags), pq.Array(filePaths),
			mem.RemediationStatus, now,
		)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("batch insert: %w", err)
		}
	}
	return tx.Commit()
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
	b.Grow(len(v)*8 + 2)
	b.WriteByte('[')
	for i, f := range v {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatFloat(float64(f), 'g', -1, 32))
	}
	b.WriteByte(']')
	return b.String()
}
