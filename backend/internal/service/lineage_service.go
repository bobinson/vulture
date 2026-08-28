package service

import (
	"fmt"
	"log"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// LineageService tracks finding lifecycle across audit runs.
type LineageService interface {
	ProcessAuditFindings(audit *model.Audit, source *model.Source, findings []model.Finding) error
	UpdateStatus(lineageID string, update *model.LineageStatusUpdate) error
	GetLineage(id string) (*model.FindingLineage, error)
	GetLineageForFinding(fingerprint, sourcePath, agentType string) (*model.FindingLineage, error)
	ListBySourcePath(sourcePath, status string, limit, offset int) ([]model.FindingLineage, error)
	ListByAudit(auditID string) ([]model.FindingLineage, error)
	GetTimeline(lineageID string) ([]model.LineageEvent, error)
}

type lineageService struct {
	repo repository.LineageRepository
}

// NewLineageService creates a new lineage service.
func NewLineageService(repo repository.LineageRepository) LineageService {
	return &lineageService{repo: repo}
}

func (s *lineageService) ProcessAuditFindings(audit *model.Audit, source *model.Source, findings []model.Finding) error {
	now := time.Now().UTC()
	currentFingerprints := map[string]bool{}
	agentTypes := map[string]bool{}

	// Collect all fingerprints for batch lookup
	fps := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Fingerprint == "" {
			continue
		}
		agentTypes[f.AgentType] = true
		// Feature 0079 A3, the dual-key bridge. Under VULTURE_FINDING_IDENTITY
		// =enforce, Fingerprint holds the NEW v2 value and LegacyFingerprint the
		// v1 one the stored rows are keyed on. Both are looked up and both count
		// as "currently present".
		//
		// Without this the first enforce run would find no match for any of the
		// 5,109 stored lineage rows, detectFixed would mark every one of them
		// FIXED, and createNewLineage would mint a fresh VLT ref for every
		// finding — a one-time destruction of human triage state
		// (accepted_risk, false_positive, notes, ticket_url).
		//
		// LegacyFingerprint is json:"-" and in no column list, so this bridge
		// lives entirely in memory and needs no backfill migration.
		for _, fp := range fingerprintsOf(f) {
			currentFingerprints[fp] = true
			fps = append(fps, fp)
		}
	}

	// Batch-fetch existing lineage records
	existingMap, err := s.repo.GetLineageByFingerprints(fps, source.Path)
	if err != nil {
		log.Printf("[lineage] batch lookup error: %v", err)
		existingMap = nil
	}

	for _, f := range findings {
		if f.Fingerprint == "" {
			continue
		}
		existing := existingMap[f.Fingerprint+"|"+f.AgentType]
		if existing == nil && f.LegacyFingerprint != "" {
			// Fall back to the pre-0079 identity so a row stored under v1 is
			// UPDATED in place rather than duplicated. updateExistingLineage
			// upserts `existing`, which still carries its original fingerprint,
			// so the row keeps its identity and its ref_number.
			existing = existingMap[f.LegacyFingerprint+"|"+f.AgentType]
		}

		if existing == nil {
			if err := s.createNewLineage(audit, source, &f, now); err != nil {
				log.Printf("[lineage] create error: %v", err)
			}
			continue
		}

		if err := s.updateExistingLineage(existing, audit, source, &f, now); err != nil {
			log.Printf("[lineage] update error id=%s: %v", existing.ID, err)
		}
	}

	// Detect fixed findings
	for agentType := range agentTypes {
		if err := s.detectFixed(audit, source, agentType, currentFingerprints); err != nil {
			log.Printf("[lineage] detect fixed error agent=%s: %v", agentType, err)
		}
	}
	return nil
}

func (s *lineageService) createNewLineage(audit *model.Audit, source *model.Source, f *model.Finding, now time.Time) error {
	l := &model.FindingLineage{
		Fingerprint:   f.Fingerprint,
		SourcePath:    source.Path,
		AgentType:     f.AgentType,
		CurrentStatus: model.LineageStatusOpen,
		FirstAuditID:  audit.ID,
		FirstFoundAt:  now,
		LatestAuditID: audit.ID,
		LatestFoundAt: &now,
		Severity:      string(f.Severity),
		Category:      f.Category,
		Title:         f.Title,
		FilePath:      f.FilePath,
		FirstCommit:   source.GitCommitShort,
		LatestCommit:  source.GitCommitShort,
	}
	if err := s.repo.UpsertLineage(l); err != nil {
		return fmt.Errorf("create lineage: %w", err)
	}
	return s.repo.AddEvent(&model.LineageEvent{
		LineageID: l.ID,
		EventType: model.LineageEventDetected,
		AuditID:   audit.ID,
		NewStatus: string(model.LineageStatusOpen),
		GitCommit: source.GitCommitShort,
		GitBranch: source.GitBranch,
	})
}

func (s *lineageService) updateExistingLineage(existing *model.FindingLineage, audit *model.Audit, source *model.Source, f *model.Finding, now time.Time) error {
	existing.LatestAuditID = audit.ID
	existing.LatestFoundAt = &now
	existing.LatestCommit = source.GitCommitShort
	if err := s.repo.UpsertLineage(existing); err != nil {
		return fmt.Errorf("update lineage: %w", err)
	}

	// Regression: was fixed, now reappeared
	if existing.CurrentStatus == model.LineageStatusFixed {
		if err := s.repo.MarkRegression(existing.ID, audit.ID, ""); err != nil {
			return fmt.Errorf("mark regression: %w", err)
		}
		return s.repo.AddEvent(&model.LineageEvent{
			LineageID: existing.ID,
			EventType: model.LineageEventRegression,
			AuditID:   audit.ID,
			OldStatus: string(model.LineageStatusFixed),
			NewStatus: string(model.LineageStatusRegression),
			GitCommit: source.GitCommitShort,
			GitBranch: source.GitBranch,
		})
	}
	return nil
}

func (s *lineageService) detectFixed(audit *model.Audit, source *model.Source, agentType string, currentFingerprints map[string]bool) error {
	openLineages, err := s.repo.GetOpenBySourcePath(source.Path, agentType)
	if err != nil {
		return fmt.Errorf("get open lineages: %w", err)
	}
	for _, ol := range openLineages {
		if currentFingerprints[ol.Fingerprint] {
			continue
		}
		// Skip user-decided statuses
		if ol.CurrentStatus == model.LineageStatusAcceptedRisk || ol.CurrentStatus == model.LineageStatusFalsePositive {
			continue
		}
		if err := s.repo.MarkFixed(ol.ID, audit.ID, source.GitCommitShort); err != nil {
			log.Printf("[lineage] mark fixed error id=%s: %v", ol.ID, err)
			continue
		}
		_ = s.repo.AddEvent(&model.LineageEvent{
			LineageID: ol.ID,
			EventType: model.LineageEventFixed,
			AuditID:   audit.ID,
			OldStatus: string(ol.CurrentStatus),
			NewStatus: string(model.LineageStatusFixed),
			GitCommit: source.GitCommitShort,
			GitBranch: source.GitBranch,
		})
	}
	return nil
}

func (s *lineageService) UpdateStatus(lineageID string, update *model.LineageStatusUpdate) error {
	existing, err := s.repo.GetLineage(lineageID)
	if err != nil {
		return fmt.Errorf("get lineage: %w", err)
	}
	if existing == nil {
		return ErrNotFound
	}

	oldStatus := string(existing.CurrentStatus)
	if err := s.repo.UpdateStatus(lineageID, update.Status, update.Notes, update.TicketURL); err != nil {
		return fmt.Errorf("update status: %w", err)
	}

	_ = s.repo.AddEvent(&model.LineageEvent{
		LineageID: lineageID,
		EventType: model.LineageEventStatusChange,
		OldStatus: oldStatus,
		NewStatus: update.Status,
	})

	if update.Notes != "" {
		_ = s.repo.AddEvent(&model.LineageEvent{
			LineageID: lineageID,
			EventType: model.LineageEventNoteAdded,
			Notes:     update.Notes,
		})
	}
	return nil
}

func (s *lineageService) GetLineage(id string) (*model.FindingLineage, error) {
	l, err := s.repo.GetLineage(id)
	if err != nil {
		return nil, fmt.Errorf("get lineage: %w", err)
	}
	if l == nil {
		return nil, ErrNotFound
	}
	return l, nil
}

func (s *lineageService) GetLineageForFinding(fingerprint, sourcePath, agentType string) (*model.FindingLineage, error) {
	l, err := s.repo.GetLineageByFingerprint(fingerprint, sourcePath, agentType)
	if err != nil {
		return nil, fmt.Errorf("get lineage by fingerprint: %w", err)
	}
	if l == nil {
		return nil, ErrNotFound
	}
	return l, nil
}

func (s *lineageService) ListBySourcePath(sourcePath, status string, limit, offset int) ([]model.FindingLineage, error) {
	return s.repo.ListBySourcePath(sourcePath, status, limit, offset)
}

func (s *lineageService) ListByAudit(auditID string) ([]model.FindingLineage, error) {
	return s.repo.ListByAudit(auditID)
}

func (s *lineageService) GetTimeline(lineageID string) ([]model.LineageEvent, error) {
	return s.repo.GetEvents(lineageID)
}

// fingerprintsOf returns every identity a finding may be stored under: its
// current fingerprint, plus the pre-0079 one when the A3 identity flip is
// active. Feature 0079 A3.
func fingerprintsOf(f model.Finding) []string {
	if f.LegacyFingerprint == "" || f.LegacyFingerprint == f.Fingerprint {
		return []string{f.Fingerprint}
	}
	return []string{f.Fingerprint, f.LegacyFingerprint}
}
