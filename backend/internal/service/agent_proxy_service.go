package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/vulture/backend/internal/agui"
	"github.com/vulture/backend/internal/model"
)

type AgentProxyService interface {
	RunAgent(ctx context.Context, agentURL string, agentType string, runID string, sourcePath string, config json.RawMessage, eventCh chan<- *model.AgUIEvent) error
	RunAgentWithContext(ctx context.Context, agentURL string, agentType string, runID string, sourcePath string, config json.RawMessage, priorFindings []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error
}

type agentProxyService struct {
	client *http.Client
}

func NewAgentProxyService() AgentProxyService {
	return &agentProxyService{client: &http.Client{}}
}

func (s *agentProxyService) RunAgent(ctx context.Context, agentURL string, agentType string, runID string, sourcePath string, config json.RawMessage, eventCh chan<- *model.AgUIEvent) error {
	return s.RunAgentWithContext(ctx, agentURL, agentType, runID, sourcePath, config, nil, eventCh)
}

func (s *agentProxyService) RunAgentWithContext(ctx context.Context, agentURL string, agentType string, runID string, sourcePath string, config json.RawMessage, priorFindings []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error {
	payload := map[string]interface{}{
		"run_id":      runID,
		"source_path": sourcePath,
		"config":      json.RawMessage(config),
	}
	if len(priorFindings) > 0 {
		payload["prior_findings"] = priorFindings
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", agentURL+"/run", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	log.Printf("[agent-proxy] calling agent=%s url=%s/run", agentType, agentURL)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("agent request: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[agent-proxy] agent=%s status=%d", agentType, resp.StatusCode)
	if resp.StatusCode != 200 {
		return fmt.Errorf("agent returned status %d", resp.StatusCode)
	}

	return s.readSSEStream(agentType, resp, eventCh)
}

func (s *agentProxyService) readSSEStream(agentType string, resp *http.Response, eventCh chan<- *model.AgUIEvent) error {
	scanner := bufio.NewScanner(resp.Body)
	// Increase buffer to handle large result events with many findings
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var currentEvent string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			currentEvent = strings.TrimPrefix(line, "event: ")
			continue
		}
		if strings.HasPrefix(line, "data: ") {
			data := json.RawMessage(strings.TrimPrefix(line, "data: "))
			log.Printf("[sse-read] agent=%s event=%s dataLen=%d", agentType, currentEvent, len(data))
			events, err := agui.Translate(agentType, currentEvent, data)
			if err != nil {
				log.Printf("[sse-read] translate error agent=%s event=%s: %v", agentType, currentEvent, err)
				continue
			}
			for _, evt := range events {
				eventCh <- evt
			}
			currentEvent = ""
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[sse-read] scanner error agent=%s: %v", agentType, err)
		return err
	}
	log.Printf("[sse-read] stream ended agent=%s", agentType)
	return nil
}
