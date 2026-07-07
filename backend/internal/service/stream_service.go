package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"sync"

	"github.com/vulture/backend/internal/agui"
	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/staging"
	"github.com/vulture/backend/pkg/pluginregistry"
	"github.com/vulture/backend/pkg/stagerouter"
)

// Feature 0063: the OWASP agent maps CWE findings onto OWASP Top 10
// categories instead of detecting. It runs as a deferred phase AFTER the
// scan agents complete, consuming the CWE-tagged findings they produced.
const (
	owaspType = "owasp"
	cweType   = "cwe"
)

var cweCategoryRe = regexp.MustCompile(`^CWE-\d+$`)

func isCWECategory(c string) bool { return cweCategoryRe.MatchString(c) }

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

	if !send(ctx, eventCh, &model.AgUIEvent{
		Type:     model.EventRunStarted,
		RunID:    audit.ID,
		ThreadID: "t-" + audit.ID,
	}) {
		return
	}

	// Feature 0063: split OWASP (a deferred mapping phase) out of the
	// concurrent scan set. When OWASP is requested, ensure CWE runs (it is
	// OWASP's prerequisite) and tap the CWE-tagged findings the scan phase
	// produces so they can be mapped afterwards.
	scanTypes, wantOwasp := splitOwasp(audit.Types)

	if !wantOwasp {
		// Pre-0063 behavior preserved exactly: dispatch audit.Types as-is
		// (an empty/nil list means "default scan" — the router expands it to
		// all enabled scan plugins). No tap needed on this path.
		if !s.dispatchScanPhase(ctx, audit, audit.Types, sourcePath, agents, priorByAgent, nil, eventCh) {
			return
		}
		send(ctx, eventCh, &model.AgUIEvent{Type: model.EventRunFinished, RunID: audit.ID})
		return
	}

	scanTypes, cweDispatched := ensureCwe(scanTypes, agents)
	tap := &cweTap{}
	// Only run a scan phase if there is something to scan. If the user asked
	// for OWASP only and CWE is unconfigured, scanTypes is empty and we must
	// NOT dispatch — an empty type list would make the router run ALL scan
	// plugins (its "no filter" default), which the user did not request.
	if len(scanTypes) > 0 {
		if !s.dispatchScanPhase(ctx, audit, scanTypes, sourcePath, agents, priorByAgent, tap, eventCh) {
			return // consumer gone
		}
	}

	s.runOwaspMapping(ctx, audit, sourcePath, agents, tap, cweDispatched, eventCh)

	send(ctx, eventCh, &model.AgUIEvent{
		Type:  model.EventRunFinished,
		RunID: audit.ID,
	})
}

// send forwards an event, honoring cancellation so a gone consumer can never
// wedge the producer (matches the launch() send discipline). Returns false if
// the context was cancelled before the send completed.
func send(ctx context.Context, ch chan<- *model.AgUIEvent, ev *model.AgUIEvent) bool {
	select {
	case ch <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

// splitOwasp separates the OWASP mapping type from the scan types.
func splitOwasp(types []string) (scan []string, wantOwasp bool) {
	for _, t := range types {
		if t == owaspType {
			wantOwasp = true
			continue
		}
		scan = append(scan, t)
	}
	return scan, wantOwasp
}

// ensureCwe adds CWE to the scan set if it isn't already present and is
// configured (OWASP's prerequisite). Returns whether CWE will be dispatched;
// if CWE isn't configured, OWASP reports cwe_stage_status="absent".
func ensureCwe(scan []string, agents map[string]config.AgentConfig) ([]string, bool) {
	for _, t := range scan {
		if t == cweType {
			return scan, true
		}
	}
	if a, ok := agents[cweType]; ok && a.URL != "" {
		return append(scan, cweType), true
	}
	return scan, false
}

// dispatchScanPhase runs the scan agents, forwarding every event to eventCh
// while tapping CWE-category findings into tap. Returns false if the consumer
// went away (context cancelled) so the caller stops cleanly.
func (s *streamService) dispatchScanPhase(ctx context.Context, audit *model.Audit, scanTypes []string, sourcePath string, agents map[string]config.AgentConfig, priorByAgent map[string][]model.PriorFinding, tap *cweTap, eventCh chan<- *model.AgUIEvent) bool {
	scanAudit := *audit
	scanAudit.Types = scanTypes

	scanCh := make(chan *model.AgUIEvent, 64)
	go func() {
		if s.router != nil {
			s.dispatchViaRouter(ctx, &scanAudit, sourcePath, agents, priorByAgent, scanCh)
		} else {
			s.dispatchLegacy(ctx, &scanAudit, sourcePath, agents, priorByAgent, scanCh)
		}
		close(scanCh)
	}()

	for ev := range scanCh {
		if tap != nil {
			tap.observe(ev)
		}
		if !send(ctx, eventCh, ev) {
			// Consumer gone: drain the scan producer so it isn't wedged on a
			// buffered send, then stop. Launch goroutines already select on
			// ctx.Done(), so this returns promptly.
			go func() {
				for range scanCh { //nolint:revive // intentional drain
				}
			}()
			return false
		}
	}
	return true
}

// runOwaspMapping launches the OWASP agent as a deferred phase, feeding it the
// CWE findings tapped from the scan phase (via the native prior_findings
// transport) plus the CWE-stage provenance. OWASP always runs when requested —
// even with zero CWE findings or a failed CWE stage — and self-reports.
func (s *streamService) runOwaspMapping(ctx context.Context, audit *model.Audit, sourcePath string, agents map[string]config.AgentConfig, tap *cweTap, cweDispatched bool, eventCh chan<- *model.AgUIEvent) {
	cfg, ok := agents[owaspType]
	if !ok || cfg.URL == "" {
		send(ctx, eventCh, agentUnavailableEvent(owaspType))
		return
	}
	findings, sawResult := tap.snapshot()
	status := cweStageStatus(cweDispatched, sawResult)
	priors := findingsToPriors(findings)

	baseCfg := extractAgentConfig(parseAuditConfigMap(audit.Config), owaspType)
	owaspCfg := withCweStatus(baseCfg, status)

	log.Printf("[stream-svc] deferred owasp mapping: cwe_findings=%d status=%s", len(priors), status)
	var wg sync.WaitGroup
	s.launch(ctx, &wg, cfg.URL, owaspType, audit.ID, sourcePath, owaspCfg, priors, eventCh)
	wg.Wait()
}

// cweStageStatus derives OWASP's cwe_stage_status POSITIVELY: "completed"
// only if the CWE agent's result snapshot was actually observed. A CWE agent
// that was unreachable emits a "thinking" unavailable notice (not RunError)
// and no snapshot, so it is correctly reported as "failed" rather than a
// misleading "completed".
func cweStageStatus(dispatched, sawResult bool) string {
	switch {
	case !dispatched:
		return "absent"
	case sawResult:
		return "completed"
	default:
		return "failed"
	}
}

// findingsToPriors converts tapped CWE findings into the prior_findings
// transport shape. code_snippet is deliberately NOT carried (snippets can
// contain secrets — feature 0063 security constraint); file+line location is.
func findingsToPriors(fs []model.Finding) []model.PriorFinding {
	out := make([]model.PriorFinding, 0, len(fs))
	for _, f := range fs {
		out = append(out, model.PriorFinding{
			Title:       f.Title,
			Severity:    string(f.Severity),
			Category:    f.Category,
			Description: f.Description,
			FilePath:    f.FilePath,
			LineStart:   f.LineStart,
			LineEnd:     f.LineEnd,
			CheckID:     f.CheckID,
		})
	}
	return out
}

// withCweStatus merges cwe_stage_status into the OWASP agent's config JSON.
func withCweStatus(cfg json.RawMessage, status string) json.RawMessage {
	m := map[string]json.RawMessage{}
	if len(cfg) > 0 {
		_ = json.Unmarshal(cfg, &m) // best-effort; start fresh on garbage
	}
	statusJSON, _ := json.Marshal(status)
	m["cwe_stage_status"] = statusJSON
	out, err := json.Marshal(m)
	if err != nil {
		return cfg
	}
	return out
}

// cweTap accumulates CWE-tagged findings from the scan phase and records
// whether the CWE agent's result snapshot arrived. observe() is called from
// the single scan-forwarding loop; the mutex guards the accessor snapshot().
type cweTap struct {
	mu           sync.Mutex
	findings     []model.Finding
	sawCweResult bool
}

func (t *cweTap) observe(ev *model.AgUIEvent) {
	if ev == nil {
		return
	}
	switch ev.Type {
	case model.EventStateDelta:
		if len(ev.Delta) == 0 {
			return
		}
		for _, f := range agui.ParseDeltaFindings(ev.Delta, ev.AgentType) {
			if isCWECategory(f.Category) {
				t.mu.Lock()
				t.findings = append(t.findings, f)
				t.mu.Unlock()
			}
		}
	case model.EventStateSnapshot:
		if ev.AgentType == cweType {
			t.mu.Lock()
			t.sawCweResult = true
			t.mu.Unlock()
		}
	}
}

func (t *cweTap) snapshot() ([]model.Finding, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fs := make([]model.Finding, len(t.findings))
	copy(fs, t.findings)
	return fs, t.sawCweResult
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
