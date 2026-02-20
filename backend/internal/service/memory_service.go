package service

import (
	"crypto/md5"
	"fmt"
	"log"
	"strings"

	"github.com/vulture/backend/internal/embedding"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// Similarity threshold for auto-linking (cosine similarity 0-1).
const autoLinkThreshold = 0.75

type MemoryService interface {
	Store(mem *model.AuditMemory) error
	Search(req *model.MemorySearchRequest) ([]model.AuditMemory, error)
	Get(id string) (*model.AuditMemory, error)
	GetWithEdges(id string) (*model.MemoryWithEdges, error)
	UpdateRemediation(id string, status string, notes string) error
	ListByAudit(auditID string) ([]model.AuditMemory, error)
	ListByCodebasePath(path string, agentType string, limit int) ([]model.AuditMemory, error)
	ListRecent(limit int) ([]model.AuditMemory, error)
	StoreFindingsAsMemories(auditID string, sourcePath string, findings []model.Finding) error
	GetEdges(memoryID string) ([]model.MemoryEdge, error)
}

type memoryService struct {
	repo     repository.MemoryRepository
	embedder *embedding.Client
}

func NewMemoryService(repo repository.MemoryRepository) MemoryService {
	return &memoryService{
		repo:     repo,
		embedder: embedding.New(),
	}
}

func (s *memoryService) Store(mem *model.AuditMemory) error {
	if mem.ID == "" {
		mem.ID = generateMemoryID(mem.AuditID, mem.Title, mem.FindingType)
	}
	if mem.RemediationStatus == "" {
		mem.RemediationStatus = "open"
	}
	if err := s.repo.StoreMemory(mem); err != nil {
		return err
	}
	// Generate embedding and auto-link asynchronously
	go s.embedAndLink(mem)
	return nil
}

// embedAndLink generates an embedding for a memory, stores it, and creates
// edges to the top 3 similar memories (auto-linking).
func (s *memoryService) embedAndLink(mem *model.AuditMemory) {
	if !s.embedder.Available() {
		return
	}
	text := buildEmbeddingText(mem)
	vec, err := s.embedder.Embed(text)
	if err != nil {
		log.Printf("[memory] embed error id=%s: %v", mem.ID, err)
		return
	}
	if err := s.repo.StoreEmbedding(mem.ID, vec); err != nil {
		log.Printf("[memory] store embedding error id=%s: %v", mem.ID, err)
		return
	}
	// Auto-link: find top 3 similar memories and create edges
	similar, err := s.repo.FindSimilarByVector(mem.ID, vec, 3)
	if err != nil {
		log.Printf("[memory] find similar error id=%s: %v", mem.ID, err)
		return
	}
	for _, sim := range similar {
		if sim.Similarity < autoLinkThreshold {
			continue
		}
		relType := inferRelationType(mem, &sim)
		edge := &model.MemoryEdge{
			SourceID:      mem.ID,
			TargetID:      sim.ID,
			RelationType:  relType,
			Strength:      sim.Similarity,
			Bidirectional: true,
			CreatedBy:     "auto-embed",
		}
		if err := s.repo.StoreEdge(edge); err != nil {
			log.Printf("[memory] store edge error: %v", err)
		}
	}
}

// batchEmbedAndLink generates embeddings for all memories in a single API call
// and creates auto-link edges for similar findings.
func (s *memoryService) batchEmbedAndLink(memories []*model.AuditMemory) {
	if !s.embedder.Available() {
		return
	}

	texts := make([]string, len(memories))
	for i, mem := range memories {
		texts[i] = buildEmbeddingText(mem)
	}

	vectors, err := s.embedder.EmbedBatch(texts)
	if err != nil {
		log.Printf("[memory] batch embed error: %v", err)
		// Fall back to individual embedding
		for _, mem := range memories {
			s.embedAndLink(mem)
		}
		return
	}

	for i, mem := range memories {
		if i >= len(vectors) {
			break
		}
		vec := vectors[i]
		if err := s.repo.StoreEmbedding(mem.ID, vec); err != nil {
			log.Printf("[memory] store embedding error id=%s: %v", mem.ID, err)
			continue
		}
		// Auto-link: find top 3 similar memories
		similar, err := s.repo.FindSimilarByVector(mem.ID, vec, 3)
		if err != nil {
			log.Printf("[memory] find similar error id=%s: %v", mem.ID, err)
			continue
		}
		for _, sim := range similar {
			if sim.Similarity < autoLinkThreshold {
				continue
			}
			edge := &model.MemoryEdge{
				SourceID:      mem.ID,
				TargetID:      sim.ID,
				RelationType:  inferRelationType(mem, &sim),
				Strength:      sim.Similarity,
				Bidirectional: true,
				CreatedBy:     "auto-embed",
			}
			if err := s.repo.StoreEdge(edge); err != nil {
				log.Printf("[memory] store edge error: %v", err)
			}
		}
	}
}

// inferRelationType determines the relationship type based on memory attributes.
func inferRelationType(source, target *model.AuditMemory) string {
	if source.FindingType == target.FindingType {
		return "same_issue"
	}
	if source.Category == target.Category {
		return "related_compliance"
	}
	return "similar"
}

func (s *memoryService) Search(req *model.MemorySearchRequest) ([]model.AuditMemory, error) {
	limit := req.Limit
	if limit <= 0 {
		limit = 20
	}
	// Try vector search first if embeddings are available
	if s.embedder.Available() {
		vec, err := s.embedder.Embed(req.Query)
		if err == nil {
			return s.repo.SearchMemories(req.Query, vec, limit)
		}
		log.Printf("[memory] search embed fallback to text: %v", err)
	}
	return s.repo.SearchMemories(req.Query, nil, limit)
}

func (s *memoryService) Get(id string) (*model.AuditMemory, error) {
	mem, err := s.repo.GetMemory(id)
	if err != nil {
		return nil, err
	}
	if mem == nil {
		return nil, ErrNotFound
	}
	return mem, nil
}

func (s *memoryService) GetWithEdges(id string) (*model.MemoryWithEdges, error) {
	mem, err := s.repo.GetMemory(id)
	if err != nil {
		return nil, err
	}
	if mem == nil {
		return nil, ErrNotFound
	}
	edges, err := s.repo.GetEdges(id)
	if err != nil {
		edges = nil // non-fatal
	}
	return &model.MemoryWithEdges{AuditMemory: *mem, Edges: edges}, nil
}

func (s *memoryService) UpdateRemediation(id string, status string, notes string) error {
	return s.repo.UpdateRemediation(id, status, notes)
}

func (s *memoryService) ListByAudit(auditID string) ([]model.AuditMemory, error) {
	return s.repo.ListMemoriesByAudit(auditID)
}

func (s *memoryService) ListByCodebasePath(path string, agentType string, limit int) ([]model.AuditMemory, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.repo.ListByCodebasePath(path, agentType, limit)
}

func (s *memoryService) StoreFindingsAsMemories(auditID string, sourcePath string, findings []model.Finding) error {
	memories := make([]*model.AuditMemory, 0, len(findings))
	for _, f := range findings {
		mem := &model.AuditMemory{
			ID:                generateMemoryID(auditID, f.Title, f.Category),
			AuditID:           auditID,
			AgentType:         f.AgentType,
			CodebasePath:      sourcePath,
			FindingType:       f.Category,
			Title:             f.Title,
			Content:           f.Description,
			Severity:          f.Severity,
			Category:          f.Category,
			Keywords:          extractKeywords(f.Title, f.Description),
			Tags:              []string{string(f.Severity), f.AgentType, f.Category},
			FilePaths:         []string{f.FilePath},
			RemediationStatus: "open",
		}
		if f.Recommendation != "" {
			mem.RemediationNotes = f.Recommendation
		}
		if err := s.repo.StoreMemory(mem); err != nil {
			return fmt.Errorf("store finding memory: %w", err)
		}
		memories = append(memories, mem)
	}

	// Batch embed and auto-link in background
	if len(memories) > 0 {
		go s.batchEmbedAndLink(memories)
	}
	return nil
}

func (s *memoryService) ListRecent(limit int) ([]model.AuditMemory, error) {
	if limit <= 0 {
		limit = 20
	}
	return s.repo.ListRecent(limit)
}

func (s *memoryService) GetEdges(memoryID string) ([]model.MemoryEdge, error) {
	return s.repo.GetEdges(memoryID)
}

func generateMemoryID(auditID, title, findingType string) string {
	h := md5.Sum([]byte(auditID + title + findingType))
	return fmt.Sprintf("%x", h)
}

func extractKeywords(title, description string) []string {
	words := strings.Fields(strings.ToLower(title + " " + description))
	seen := map[string]bool{}
	var keywords []string
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "is": true, "are": true,
		"was": true, "were": true, "be": true, "been": true, "being": true,
		"have": true, "has": true, "had": true, "do": true, "does": true,
		"did": true, "will": true, "would": true, "could": true, "should": true,
		"may": true, "might": true, "must": true, "shall": true, "can": true,
		"of": true, "in": true, "to": true, "for": true, "with": true,
		"on": true, "at": true, "from": true, "by": true, "about": true,
		"as": true, "into": true, "through": true, "and": true, "or": true,
		"but": true, "not": true, "no": true, "if": true, "then": true,
		"that": true, "this": true, "it": true, "its": true, "than": true,
	}
	for _, w := range words {
		clean := strings.Trim(w, ".,;:!?()[]{}\"'")
		if len(clean) < 3 || stopWords[clean] || seen[clean] {
			continue
		}
		seen[clean] = true
		keywords = append(keywords, clean)
		if len(keywords) >= 15 {
			break
		}
	}
	return keywords
}

// buildEmbeddingText creates a rich text representation for embedding.
func buildEmbeddingText(mem *model.AuditMemory) string {
	parts := []string{
		mem.Title,
		mem.Content,
		"Category: " + mem.Category,
		"Severity: " + string(mem.Severity),
	}
	if mem.ComplianceRef != "" {
		parts = append(parts, "Compliance: "+mem.ComplianceRef)
	}
	if len(mem.FilePaths) > 0 {
		parts = append(parts, "Files: "+strings.Join(mem.FilePaths, ", "))
	}
	return strings.Join(parts, "\n")
}
