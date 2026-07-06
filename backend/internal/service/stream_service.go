package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/staging"
	"github.com/vulture/backend/pkg/pluginregistry"
	"github.com/vulture/backend/pkg/stagerouter"
)

type StreamService interface {
	Stream(ctx context.Context, audit *model.Audit, sourcePath string, agents map[string]config.AgentConfig, eventCh chan<- *model.AgUIEvent)
	StreamWithContext(ctx context.Context, audit *model.Audit, sourcePath string, agents map[string]config.AgentConfig, priorByAgent map[string][]model.PriorFinding, eventCh chan<- *model.AgUIEvent)
}

type streamService struct {
	proxy  AgentProxyService
	router stagerouter.Router
}

// NewStreamService constructs the stream service with the legacy
// audit.Types dispatch path. Used by callers that haven't wired the
// plugin registry yet (notably some tests).
func NewStreamService(proxy AgentProxyService) StreamService {
	return &streamService{proxy: proxy}
}

// NewStreamServiceWithRouter constructs the stream service with a
// stage router for capability-based dispatch. Whenever a non-nil
// router is wired, dispatch goes through the router. The legacy
// audit.Types path remains as a fallback for the nil-router case
// (used by tests + degraded-mode startup when the registry didn't
// build). The previous VULTURE_STAGE_ROUTER feature flag was removed
// once the router shipped cleanly through 0050/0051/0052/0053.
func NewStreamServiceWithRouter(proxy AgentProxyService, router stagerouter.Router) StreamService {
	return &streamService{proxy: proxy, router: router}
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

	if s.router != nil {
		s.dispatchViaRouter(ctx, audit, sourcePath, agents, priorByAgent, eventCh)
	} else {
		s.dispatchLegacy(ctx, audit, sourcePath, agents, priorByAgent, eventCh)
	}

	eventCh <- &model.AgUIEvent{
		Type:  model.EventRunFinished,
		RunID: audit.ID,
	}
}

// dispatchLegacy is the pre-0049 path: iterate audit.Types, look up
// cfg.Agents, fan out goroutines. Used when no stage router is wired
// (NewStreamService callers + degraded-mode startup).
func (s *streamService) dispatchLegacy(ctx context.Context, audit *model.Audit, sourcePath string, agents map[string]config.AgentConfig, priorByAgent map[string][]model.PriorFinding, eventCh chan<- *model.AgUIEvent) {
	cfgMap := parseAuditConfigMap(audit.Config)
	var wg sync.WaitGroup
	for _, auditType := range audit.Types {
		agentCfg, ok := agents[auditType]
		if !ok || agentCfg.URL == "" {
			log.Printf("[stream-svc] skipping agent=%s (not configured)", auditType)
			continue
		}
		agentConfig := extractAgentConfig(cfgMap, auditType)
		prior := priorByAgent[auditType]
		log.Printf("[stream-svc] launching agent=%s url=%s", auditType, agentCfg.URL)
		s.launch(ctx, &wg, agentCfg.URL, auditType, audit.ID, sourcePath, agentConfig, prior, eventCh)
	}
	wg.Wait()
	log.Printf("[stream-svc] all agents done for audit=%s", audit.ID)
}

// dispatchViaRouter consults stagerouter to pick scan-stage targets.
// Each DispatchTarget becomes one goroutine. Duplicates (same plugin,
// multiple capabilities) are deduped by PluginName here so the
// downstream agent isn't called twice for the same audit.
//
// When the router returns zero targets BUT audit.Types is non-empty,
// fall back to legacy dispatch. This handles audits naming a plugin
// whose capability is in a non-scan stage (e.g. prove, discover) —
// the router currently hardcodes Stage=Scan; legacy-by-name still
// works. Without this, `types=['prove']` audits silently no-op.
// (Bug introduced when the VULTURE_STAGE_ROUTER feature flag was
// removed; the legacy path was the previous safety net.)
func (s *streamService) dispatchViaRouter(ctx context.Context, audit *model.Audit, sourcePath string, agents map[string]config.AgentConfig, priorByAgent map[string][]model.PriorFinding, eventCh chan<- *model.AgUIEvent) {
	cfgMap := parseAuditConfigMap(audit.Config)
	targets, err := s.router.Route(stagerouter.RouteRequest{
		Stage:          stagerouter.StageScan,
		RequestedTypes: audit.Types,
	})
	if err != nil {
		log.Printf("[stream-svc] router error: %v (falling back to legacy)", err)
		s.dispatchLegacy(ctx, audit, sourcePath, agents, priorByAgent, eventCh)
		return
	}
	if len(targets) == 0 && len(audit.Types) > 0 {
		log.Printf("[stream-svc] router returned 0 scan targets for types=%v; falling back to legacy (likely a prove/discover/validate audit)", audit.Types)
		s.dispatchLegacy(ctx, audit, sourcePath, agents, priorByAgent, eventCh)
		return
	}
	// LocalMode (native launcher): container plugins mount only the
	// staging root (AuditsDir) at AuditInputsMount, so the audit's source
	// is staged into AuditsDir/<audit-id>/ and dispatched by its staged
	// container path. Native agents (and docker-compose) keep the raw
	// path. Staged lazily on first container target; reaped when all
	// agents finish (feature 0058 P0c/P0d).
	stager := &containerStager{
		localMode:  os.Getenv("VULTURE_LOCAL_MODE") == "true",
		auditID:    audit.ID,
		sourcePath: sourcePath,
		auditsDir:  staging.AuditsDirFromEnv(),
	}
	defer stager.reap() // runs after wg.Wait below
	var wg sync.WaitGroup
	seen := make(map[string]bool, len(targets))
	for _, t := range targets {
		if seen[t.PluginName] {
			continue
		}
		seen[t.PluginName] = true
		agentConfig := extractAgentConfig(cfgMap, t.PluginName)
		prior := priorByAgent[t.PluginName]
		src, ok := stager.sourceFor(ctx, t.RuntimeType == pluginregistry.RuntimeContainer)
		if !ok {
			log.Printf("[stream-svc] skipping agent=%s for audit=%s: source staging failed: %v (other agents proceed)", t.PluginName, audit.ID, stager.stageErr)
			continue
		}
		log.Printf("[stream-svc] router dispatch agent=%s url=%s source=%s", t.PluginName, t.URL, src)
		s.launch(ctx, &wg, t.URL, t.PluginName, audit.ID, src, agentConfig, prior, eventCh)
	}
	wg.Wait()
	log.Printf("[stream-svc] all router-dispatched agents done for audit=%s", audit.ID)
}

// containerStager lazily stages the audit source into the staging root
// the first time a container-runtime target is dispatched in local mode
// (feature 0058 P0c/P0d) and reaps the staged tree once the audit's
// agents finish. Non-container targets and compose mode keep the exact
// pre-0058 ContainerSourcePath semantics (raw path).
type containerStager struct {
	localMode  bool
	auditID    string
	sourcePath string
	auditsDir  string
	staged     bool
	stageErr   error
}

// sourceFor returns the source_path to dispatch to a target. ok=false
// means staging failed and the target must be skipped gracefully.
func (c *containerStager) sourceFor(ctx context.Context, isContainer bool) (string, bool) {
	if !c.localMode || !isContainer {
		// Compose mode / native agents: unchanged 0055 behavior (this
		// call returns the raw path in exactly these cases).
		return pluginregistry.ContainerSourcePath(c.localMode, isContainer, c.sourcePath), true
	}
	if c.ensureStaged(ctx) != nil {
		return "", false
	}
	return staging.StagedContainerPath(c.auditID), true
}

// ensureStaged runs Stage at most once; later targets reuse the result.
func (c *containerStager) ensureStaged(ctx context.Context) error {
	if !c.staged {
		c.staged = true
		_, c.stageErr = staging.Stage(ctx, c.sourcePath, c.auditsDir, c.auditID)
	}
	return c.stageErr
}

// reap removes the staged tree if one was created (or attempted).
func (c *containerStager) reap() {
	if !c.staged || c.stageErr != nil {
		return
	}
	if err := staging.Reap(c.auditsDir, c.auditID); err != nil {
		log.Printf("[stream-svc] staging reap failed audit=%s: %v", c.auditID, err)
	}
}

func (s *streamService) launch(ctx context.Context, wg *sync.WaitGroup, url, agentType, auditID, sourcePath string, agentConfig json.RawMessage, prior []model.PriorFinding, eventCh chan<- *model.AgUIEvent) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.proxy.RunAgentWithContext(ctx, url, agentType, auditID, sourcePath, agentConfig, prior, eventCh); err != nil {
			// Graceful degradation (feature 0058 R9/P1c): an unreachable
			// agent is an augmentation tier that isn't active, not an
			// audit failure. Emit a notice and let the other agents flow.
			log.Printf("[stream-svc] agent=%s error: %v", agentType, err)
			// Honor cancellation on the send: a stopped/gone consumer must
			// never wedge this goroutine, which would hang wg.Wait() and
			// leak the staged tree (reap never runs). Matches the proxy's
			// send discipline (0058 review, MEDIUM).
			select {
			case eventCh <- agentUnavailableEvent(agentType):
			case <-ctx.Done():
			}
		} else {
			log.Printf("[stream-svc] agent=%s completed successfully", agentType)
		}
	}()
}

// agentUnavailableEvent builds the "thinking" notice emitted when an
// agent's proxy call fails (feature 0058 T7, LLD R9): the tier is
// reported as not active and the audit continues without it.
//
// CONTRACT: the "<agent> tier not active" phrase is pinned — the
// frontend (SemgrepTierNotice.tsx) string-matches it to show the
// graceful-absence banner, and the T7 tests assert it. If you change
// the wording, change both sides and the tests together.
func agentUnavailableEvent(agentType string) *model.AgUIEvent {
	delta, _ := json.Marshal(fmt.Sprintf(
		"%s tier not active (agent unavailable); continuing with the remaining agents", agentType))
	return &model.AgUIEvent{
		Type:      model.AgUIEventType("thinking"),
		MessageID: "msg-thinking",
		Delta:     delta,
		AgentType: agentType,
	}
}

func parseAuditConfigMap(raw json.RawMessage) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

func extractAgentConfig(cfgMap map[string]json.RawMessage, agentType string) json.RawMessage {
	if cfgMap == nil {
		return json.RawMessage("{}")
	}
	if ac, ok := cfgMap[agentType]; ok {
		return ac
	}
	return json.RawMessage("{}")
}
