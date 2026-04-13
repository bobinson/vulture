package service

import (
	"context"
	"encoding/json"
	"log"
	"sync"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
)

type StreamService interface {
	Stream(ctx context.Context, audit *model.Audit, sourcePath string, agents map[string]config.AgentConfig, eventCh chan<- *model.AgUIEvent)
	StreamWithContext(ctx context.Context, audit *model.Audit, sourcePath string, agents map[string]config.AgentConfig, priorByAgent map[string][]model.PriorFinding, eventCh chan<- *model.AgUIEvent)
}

type streamService struct {
	proxy AgentProxyService
}

func NewStreamService(proxy AgentProxyService) StreamService {
	return &streamService{proxy: proxy}
}

func (s *streamService) Stream(ctx context.Context, audit *model.Audit, sourcePath string, agents map[string]config.AgentConfig, eventCh chan<- *model.AgUIEvent) {
	s.StreamWithContext(ctx, audit, sourcePath, agents, nil, eventCh)
}

func (s *streamService) StreamWithContext(ctx context.Context, audit *model.Audit, sourcePath string, agents map[string]config.AgentConfig, priorByAgent map[string][]model.PriorFinding, eventCh chan<- *model.AgUIEvent) {
	defer close(eventCh)

	eventCh <- &model.AgUIEvent{
		Type:     model.EventRunStarted,
		RunID:    audit.ID,
		ThreadID: "t-" + audit.ID,
	}

	// Pre-parse config once before goroutine loop to avoid N re-parses
	var cfgMap map[string]json.RawMessage
	if err := json.Unmarshal(audit.Config, &cfgMap); err != nil {
		cfgMap = nil
	}

	var wg sync.WaitGroup
	for _, auditType := range audit.Types {
		agentCfg, ok := agents[auditType]
		if !ok || agentCfg.URL == "" {
			log.Printf("[stream-svc] skipping agent=%s (not configured)", auditType)
			continue
		}

		// Extract agent config from pre-parsed map
		agentConfig := json.RawMessage("{}")
		if cfgMap != nil {
			if ac, ok := cfgMap[auditType]; ok {
				agentConfig = ac
			}
		}
		prior := priorByAgent[auditType]

		log.Printf("[stream-svc] launching agent=%s url=%s", auditType, agentCfg.URL)
		wg.Add(1)
		go func(at string, ac config.AgentConfig, agCfg json.RawMessage, pr []model.PriorFinding) {
			defer wg.Done()
			if err := s.proxy.RunAgentWithContext(ctx, ac.URL, at, audit.ID, sourcePath, agCfg, pr, eventCh); err != nil {
				log.Printf("[stream-svc] agent=%s error: %v", at, err)
			} else {
				log.Printf("[stream-svc] agent=%s completed successfully", at)
			}
		}(auditType, agentCfg, agentConfig, prior)
	}

	wg.Wait()
	log.Printf("[stream-svc] all agents done for audit=%s", audit.ID)

	eventCh <- &model.AgUIEvent{
		Type:  model.EventRunFinished,
		RunID: audit.ID,
	}
}
