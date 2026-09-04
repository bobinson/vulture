package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/vulture/backend/internal/agui"
	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/staging"
	"github.com/vulture/backend/pkg/agentregistry"
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
			// Evidence, so the mapping agent inherits rather than strips it.
			Provenance:           f.Provenance,
			ValidationStatus:     f.ValidationStatus,
			ValidationConfidence: f.ValidationConfidence,
			Validation:           f.Validation,
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
	mu sync.Mutex
	// deltas holds every CWE-categorised row seen on the per-finding delta
	// path, keyed by the agent that emitted it. Any agent may emit a
	// CWE-categorised finding — xss emits CWE-79/113/644/1336 — so this is
	// deliberately not restricted to the cwe agent.
	deltas map[string][]model.Finding
	// snapshots holds the PARSEABLE CWE-categorised rows from each agent's
	// result report, keyed the same way (feature 0082 C5: both branches must
	// filter identically; before 0082 the delta branch accepted every agent
	// while the snapshot branch accepted only "cwe", so an xss row could never
	// be superseded by its own finished report).
	snapshots map[string][]model.Finding
	malformed map[string]int
	// sawSnapshot records that an agent sent a result event AT ALL, parseable
	// or not, with CWE-categorised rows or not. Kept distinct from
	// len(snapshots[a]) because the rollback path must reproduce the pre-0082
	// meaning of "the stage finished" exactly: that a snapshot event arrived.
	// Conflating the two silently re-graded a CWE agent whose report carried no
	// CWE-categorised rows from "completed" to "failed" on the DEFAULT path.
	sawSnapshot map[string]bool
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
				if t.deltas == nil {
					t.deltas = map[string][]model.Finding{}
				}
				t.deltas[f.AgentType] = append(t.deltas[f.AgentType], f)
				t.mu.Unlock()
			}
		}
	case model.EventStateSnapshot:
		if len(ev.Snapshot) == 0 {
			return
		}
		// Per-ROW parse (feature 0082 C3). The previous whole-payload unmarshal
		// meant one row carrying `"line_start": "55"` took the entire report to
		// zero, and VULTURE_LLM_COERCE_LINES is a documented rollback switch
		// that re-arms exactly that shape.
		parsed, malformed := agui.ParseSnapshotFindings(ev.Snapshot, ev.AgentType)
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.snapshots == nil {
			t.snapshots = map[string][]model.Finding{}
			t.malformed = map[string]int{}
			t.sawSnapshot = map[string]bool{}
		}
		t.sawSnapshot[ev.AgentType] = true
		t.malformed[ev.AgentType] += malformed
		for _, f := range parsed {
			if isCWECategory(f.Category) {
				t.snapshots[ev.AgentType] = append(t.snapshots[ev.AgentType], f)
			}
		}
	}
}

// snapshot resolves what the OWASP mapping stage receives, and whether the CWE
// stage genuinely finished.
//
// RESOLUTION RULE (feature 0082 C6): PER-AGENT all-or-nothing, matching
// drainResultAt's persistence rule (handler/stream_handler.go). An agent that
// produced at least one parseable CWE row in its finished report contributes
// exactly that report; its deltas are discarded. An agent that produced none
// contributes its deltas. A per-KEY merge was rejected: it made OWASP's priors
// a strict superset of the PERSISTED CWE set, so every row that
// _collapse_skill_findings deliberately dropped after its delta had already
// streamed became an OWASP finding whose CWE twin is absent from the database
// — a phantom — and inflated the coverage manifest's `detected` set.
//
// This is unconditional. It shipped behind VULTURE_OWASP_CONSUME_SNAPSHOT
// (default off, then default on after a like-for-like gate run on juice-shop:
// cwe/asvs/xss unchanged, owasp 342 -> 341 where the one dropped row was such a
// phantom, OWASP rows carrying a real verdict 0/342 -> 341/341). The switch was
// then removed at the owner's direction: the only thing it could restore was
// the pre-0082 defect — pre-enrichment delta rows, every OWASP verdict empty
// and then SYNTHESISED by the backend, plus the phantoms. Rolling this back now
// means reverting this function and observe() to the delta-only tap, not
// flipping a flag.
//
// IDENTITY (C1): rows are never keyed on (path, line, category). A rollup
// parent's line_start is min(member line_starts) and it copies the group's
// category and file_path verbatim, so on that tuple every parent is identical
// to its own lowest-line child — 69/69 on the reference scan. The per-agent
// rule needs no key at all, which is the other reason it was chosen; the
// distinctness of parent and child is asserted by TestTapIsLossless.
//
// COLLISION (C7): when several CWE rows map to one OWASP category at one
// (path, line), the surviving row is chosen downstream by severity and then by
// tieBreakKey's lexical order (handler.findingDetailScore / tieBreakKey). That
// selection reads no validation field: it is NOT evidence-ranked.
//
// Returns the findings and whether the CWE stage completed. "Completed" means
// a report ARRIVED and was intelligible — at least one parseable row, or a
// valid report with zero rows (a clean repository). What is NOT completed is a
// report whose rows were all unparseable: that yields zero priors and a
// zero-coverage manifest indistinguishable from the clean case.
func (t *cweTap) snapshot() ([]model.Finding, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Every agent that streamed a CWE row OR sent a report. The second set is
	// required: a CLEAN agent has no deltas and no snapshot rows, so building
	// the set from rows alone never visits it and misreports the stage as
	// unfinished. t.snapshots' keys are always a subset of t.sawSnapshot's.
	agentSet := make(map[string]struct{}, len(t.deltas)+len(t.sawSnapshot))
	for a := range t.deltas {
		agentSet[a] = struct{}{}
	}
	for a := range t.sawSnapshot {
		agentSet[a] = struct{}{}
	}
	// Sorted so prior order — and therefore the OWASP agent's per-row index and
	// the ids derived from it — is deterministic for a given event stream
	// rather than following map iteration order.
	agents := make([]string, 0, len(agentSet))
	for a := range agentSet {
		agents = append(agents, a)
	}
	sort.Strings(agents)

	out := make([]model.Finding, 0, 64)
	cweCompleted := false
	for _, a := range agents {
		reported := t.snapshots[a]

		// "Did this agent finish?" and "did it find anything?" are DIFFERENT
		// questions, and conflating them reports a genuinely clean repository
		// as a FAILED stage.
		if a == cweType && t.sawSnapshot[a] && (len(reported) > 0 || t.malformed[a] == 0) {
			cweCompleted = true
		}

		if len(reported) > 0 {
			out = append(out, reported...)
			continue
		}
		// No parseable rows in the report. Fall back to this agent's deltas so
		// a report we could not read never costs findings the stream already
		// carried. Harmless for a genuinely clean agent: it has no deltas
		// either, and the fallback contributes nothing.
		if t.malformed[a] > 0 {
			log.Printf("[cwe-tap] agent=%s reported %d rows, ALL unparseable — falling back to %d delta rows (agent_truncated)",
				a, t.malformed[a], len(t.deltas[a]))
		}
		out = append(out, t.deltas[a]...)
	}
	return out, cweCompleted
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
			log.Printf("[stream-svc] skipping agent=%s (not configured)", strconv.Quote(auditType))
			continue
		}
		agentConfig := extractAgentConfig(cfgMap, auditType)
		prior := priorByAgent[auditType]
		// 0065 §L5: quote request/manifest-derived fields so a CR/LF cannot forge a log record.
		log.Printf("[stream-svc] launching agent=%s url=%s", strconv.Quote(auditType), strconv.Quote(agentCfg.URL))
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
			log.Printf("[stream-svc] skipping agent=%s for audit=%s: source staging failed: %v (other agents proceed)", strconv.Quote(t.PluginName), audit.ID, stager.stageErr)
			continue
		}
		// 0065 §L5: quote manifest-derived name/url and staged source path.
		log.Printf("[stream-svc] router dispatch agent=%s url=%s source=%s", strconv.Quote(t.PluginName), strconv.Quote(t.URL), strconv.Quote(src))
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

// extractAgentConfig returns the config one agent should receive: every
// non-agent-type ("flat") key from the audit config, with that agent's own
// block merged over the top.
//
// Feature 0081. Before this it was `cfgMap[agentType]` or `{}`, so a flat key
// was silently discarded — and four shipped things depended on the flat form:
//
//	CLI --validate-llm  {"validate":{"llm":true}}  -> {}  L5 judge never enabled
//	CLI --llm-tier3     {"llm_tier3":true}         -> {}  sweep never widened
//	pipeline discover   {"target_url":...}         -> {}  target URL never sent
//	pipeline prove      {"staging_url":...}        -> {}  staging URL never sent
//
// The flat form is an internal CONVENTION, not a client mistake: the largest
// producer is Vulture's own GetStageAuditConfig. An earlier draft of this fix
// proposed rejecting unrecognised keys with a 400 and would therefore have
// broken every pipeline stage.
//
// A pipeline stage runs one agent type, so a flat per-stage value reaches
// exactly its intended agent. In a multi-agent audit a flat key also reaches
// agents that do not read it, which is harmless: no agent validates its config
// (they declare additionalProperties:false in config_schema and nothing
// enforces it at runtime).
func extractAgentConfig(cfgMap map[string]json.RawMessage, agentType string) json.RawMessage {
	if cfgMap == nil {
		return json.RawMessage("{}")
	}
	own, hasOwn := cfgMap[agentType]
	if !configMergeEnabled() {
		if hasOwn {
			return own
		}
		return json.RawMessage("{}")
	}
	merged := make(map[string]json.RawMessage, len(cfgMap))
	known := knownAgentTypes()
	var flat []string
	for k, v := range cfgMap {
		if known[k] {
			continue // another agent's block; never cross-contaminate
		}
		merged[k] = v
		flat = append(flat, k)
	}
	// The agent's own block wins on conflict: a global default with a per-agent
	// override is the useful shape, and the reverse never is.
	if hasOwn {
		var ownMap map[string]json.RawMessage
		if err := json.Unmarshal(own, &ownMap); err != nil {
			// A non-object per-agent block is not mergeable. Preserve the
			// pre-0081 behaviour for it rather than dropping it.
			return own
		}
		for k, v := range ownMap {
			merged[k] = v
		}
	}
	if len(merged) == 0 {
		return json.RawMessage("{}")
	}
	if len(flat) > 0 {
		sort.Strings(flat)
		log.Printf("[config] agent=%s merged non-agent keys: %v", agentType, flat)
	}
	out, err := json.Marshal(merged)
	if err != nil {
		return json.RawMessage("{}")
	}
	return out
}

// configMergeEnabled gates feature 0081. VULTURE_AUDIT_CONFIG_MERGE=false
// restores per-agent-only routing exactly, re-breaking the four cases above.
// Read at call time so the switch stays flippable.
func configMergeEnabled() bool {
	if v := strings.TrimSpace(os.Getenv("VULTURE_AUDIT_CONFIG_MERGE")); v != "" {
		return config.EnvTruthy("VULTURE_AUDIT_CONFIG_MERGE")
	}
	return true
}

// knownAgentTypes is every key that addresses ONE agent rather than all of them.
//
// Built from AllAgents, NOT ScanAgentTypes(): that helper excludes prove and
// discover because they are pipeline stages rather than scanners, and treating
// them as flat keys would merge `{"prove":{...}}` into every agent's config.
// Plugin names come from the live registry, so a plugin such as semgrep routes
// correctly with no edit here.
func knownAgentTypes() map[string]bool {
	known := make(map[string]bool, len(agentregistry.AllAgents)+4)
	for _, a := range agentregistry.AllAgents {
		known[a.Type] = true
	}
	for _, pl := range pluginregistry.Default().All() {
		known[pl.Name()] = true
	}
	return known
}
