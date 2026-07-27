package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vulture/backend/internal/agui"
	"github.com/vulture/backend/internal/model"
)

type AgentProxyService interface {
	RunAgent(ctx context.Context, agentURL string, agentType string, runID string, sourcePath string, config json.RawMessage, eventCh chan<- *model.AgUIEvent) error
	RunAgentWithContext(ctx context.Context, agentURL string, agentType string, runID string, sourcePath string, config json.RawMessage, priorFindings []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error
}

// BrokerMinter mints the per-run LLM-broker token injected into an agent
// dispatch (feature 0064 §6/§25.2). Satisfied by broker/serve.Broker; nil (or
// a disabled broker returning "") leaves Mode A behavior unchanged.
type BrokerMinter interface {
	MintForAgent(runID, taskType string) (string, error)
	// ContextWindow resolves the run model's context window (tokens) via the
	// broker registry (§31); 0 when disabled/unknown (nothing injected).
	ContextWindow() int
}

type agentProxyService struct {
	client *http.Client
	minter BrokerMinter
	// auditTimeout bounds a whole per-agent audit (env
	// VULTURE_AGENT_PROXY_TIMEOUT_SEC, default 600s). A slow local model
	// (LM Studio/Ollama) scanning a large tree may need longer than the historical
	// 10-minute cap; raise this to let it finish. Should be >= the agent's own
	// VULTURE_AGENT_MAX_AUDIT_SECONDS ceiling so the backend doesn't cut the agent
	// off first.
	auditTimeout time.Duration
	// respHeaderTimeout is how long to wait for the agent's response headers
	// (env VULTURE_AGENT_RESPONSE_HEADER_TIMEOUT_SEC, default 300s).
	respHeaderTimeout time.Duration
}

// Default per-agent timeouts (seconds), preserved from the historical hardcoded
// values so behavior is unchanged when the env vars are unset.
const (
	defaultAgentProxyTimeoutSec      = 600 // 10 minutes
	defaultAgentRespHeaderTimeoutSec = 300
)

// NewAgentProxyService builds the proxy. minter may be nil (broker off) — then
// no broker_token is injected and agents use their env provider keys (Mode A).
// The two per-agent timeouts are env-configurable (see the struct fields).
func NewAgentProxyService(minter BrokerMinter) AgentProxyService {
	auditTimeout := envDurationSec("VULTURE_AGENT_PROXY_TIMEOUT_SEC", defaultAgentProxyTimeoutSec)
	respHeaderTimeout := envDurationSec("VULTURE_AGENT_RESPONSE_HEADER_TIMEOUT_SEC", defaultAgentRespHeaderTimeoutSec)
	// Surface the RESOLVED timeouts so an operator can confirm an override
	// actually took effect (env must be visible to THIS process — in vulture.sh
	// dev it must live in .env, not just the shell).
	log.Printf("[agent-proxy] audit_timeout=%s response_header_timeout=%s (override via VULTURE_AGENT_PROXY_TIMEOUT_SEC / _RESPONSE_HEADER_TIMEOUT_SEC)", auditTimeout, respHeaderTimeout)
	return &agentProxyService{
		minter:            minter,
		auditTimeout:      auditTimeout,
		respHeaderTimeout: respHeaderTimeout,
		client: &http.Client{
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				ResponseHeaderTimeout: respHeaderTimeout,
				MaxIdleConns:          20,
				MaxIdleConnsPerHost:   10,
				IdleConnTimeout:       120 * time.Second,
			},
		},
	}
}

// envDurationSec reads an integer-seconds env var, returning fallbackSec seconds
// when it is unset, non-numeric, or <= 0. It tolerates a trailing inline comment
// or extra whitespace tokens (e.g. a quoted .env value like `"1800 # 30 min"`),
// which would otherwise silently fall back to the default and mask an override.
func envDurationSec(key string, fallbackSec int) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if i := strings.IndexAny(v, " \t#"); i >= 0 {
		v = v[:i] // keep only the leading token
	}
	if v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return time.Duration(fallbackSec) * time.Second
}

func (s *agentProxyService) RunAgent(ctx context.Context, agentURL string, agentType string, runID string, sourcePath string, config json.RawMessage, eventCh chan<- *model.AgUIEvent) error {
	return s.RunAgentWithContext(ctx, agentURL, agentType, runID, sourcePath, config, nil, eventCh)
}

func (s *agentProxyService) RunAgentWithContext(ctx context.Context, agentURL string, agentType string, runID string, sourcePath string, config json.RawMessage, priorFindings []model.PriorFinding, eventCh chan<- *model.AgUIEvent) error {
	// Wrap caller context with the configured max audit duration (env
	// VULTURE_AGENT_PROXY_TIMEOUT_SEC, default 600s).
	ctx, cancel := context.WithTimeout(ctx, s.auditTimeout)
	defer cancel()

	payload := map[string]interface{}{
		"run_id":      runID,
		"source_path": sourcePath,
		"config":      json.RawMessage(config),
	}
	if len(priorFindings) > 0 {
		payload["prior_findings"] = priorFindings
	}
	// Feature 0064 §25.2: when the broker is enabled, mint a per-run token
	// scoped to this agent's task_type and inject it (+ task_type for the
	// X-Vulture-Task-Type header the agent sends). A disabled broker returns
	// "", so nothing changes in Mode A.
	if s.minter != nil {
		if tok, err := s.minter.MintForAgent(runID, agentType); err != nil {
			log.Printf("[agent-proxy] broker mint failed for run=%s agent=%s: %v", runID, agentType, err)
		} else if tok != "" {
			payload["broker_token"] = tok
			payload["task_type"] = agentType
			// §31: inject the broker-resolved model context window so the agent
			// sizes its LLM phase from the registry, not a timid local default.
			if cw := s.minter.ContextWindow(); cw > 0 {
				payload["context_window"] = cw
			}
		}
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
	if token := os.Getenv("VULTURE_AGENT_TOKEN"); token != "" {
		req.Header.Set("X-Vulture-Agent-Token", token)
	}

	// 0065 §L5: quote the manifest/config-derived agent URL against log injection.
	log.Printf("[agent-proxy] calling agent=%s url=%s/run", agentType, strconv.Quote(agentURL))
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("agent request: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[agent-proxy] agent=%s status=%d", agentType, resp.StatusCode)
	if resp.StatusCode != 200 {
		return fmt.Errorf("agent returned status %d", resp.StatusCode)
	}

	return s.readSSEStream(ctx, agentType, resp, eventCh)
}

func (s *agentProxyService) readSSEStream(ctx context.Context, agentType string, resp *http.Response, eventCh chan<- *model.AgUIEvent) error {
	scanner := bufio.NewScanner(resp.Body)
	// Increase buffer to handle large result events with many findings.
	// 16MB allows ~1000+ findings in a single result payload.
	// Validated: 215 findings × ~2KB each ≈ 430KB, well within 16MB limit.
	scanner.Buffer(make([]byte, 0, 4096), 16*1024*1024)
	var currentEvent string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			currentEvent = strings.TrimPrefix(line, "event: ")
			continue
		}
		if strings.HasPrefix(line, "data: ") {
			data := json.RawMessage(strings.TrimPrefix(line, "data: "))
			events, err := agui.Translate(agentType, currentEvent, data)
			if err != nil {
				log.Printf("[sse-read] translate error agent=%s event=%s: %v", agentType, currentEvent, err)
				continue
			}
			for _, evt := range events {
				select {
				case eventCh <- evt:
				case <-ctx.Done():
					return ctx.Err()
				}
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
