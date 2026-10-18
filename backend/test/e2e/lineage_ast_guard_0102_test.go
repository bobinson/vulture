//go:build e2e

package e2e

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/agui"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

// Feature 0102 D24 — a file the AST tier could not parse this run is not a
// file the AST tier re-read, so its silence about that file is not repair.
//
// THE DEFECT. An AST-owned finding carries provenance "skill", so it is
// deterministic-tier and closes on absence. But the regex tier cannot
// reproduce an AST-only flow (multi-statement, call-result carrier, same-file
// callee sink). So whenever the file it lives in falls back to regex on a
// later scan — parse_error, timeout, too_large, ..., or the circuit_open
// mass-trip — the still-present vulnerability is silently closed as FIXED and
// audit_memories is synced to `resolved`. One injected syntax error is enough
// to trigger it.
//
// THE CONTRACT (LLD D24, plan task 3.4b). Before a deterministic row whose
// category the AST tier owns (CWE-22, CWE-918, CWE-78) is closed, the pass
// consults the agent's streamed `result.ast_coverage.files`:
//
//   - breaker_tripped == true          -> hold EVERY such row `unconfirmed`
//   - row file ∈ fallback_keys         -> hold that row `unconfirmed`
//   - row file cannot be placed        -> hold (never close)
//   - ast_coverage present, malformed  -> hold (fail safe)
//   - ast_coverage ABSENT              -> no guard: today's behaviour
//
// Membership is tested on `fallback_keys` — canonical root-relative, lossless,
// uncapped — NEVER on the safe_path-rendered, 200-capped `fallback_paths`
// display list. Held means `unconfirmed`, never `fixed`, and the memory row is
// never synced to `resolved`.
//
// Every test builds the agent's result through agui.ParseScanOutcome — the
// exact parser the stream handler runs on the agent's `result` snapshot — and
// then attaches the findings, as recordLineageOutcomes does. So these tests pin
// the whole backend read (parse -> thread -> guard), not a Go field name.
//
// Each test carries a CONTROL that still closes, so "stop closing anything"
// cannot pass for the fix.

// astFallbackFile is a file the AST tier fell back on in scan 2.
const astFallbackFile = "src/routes/files.js"

// astParsedFile is a file the AST tier parsed cleanly in scan 2: it really
// re-read it, so a finding missing from it is evidence.
const astParsedFile = "src/routes/parsed.js"

// astNonASCIIPath and astLongPath are the two path shapes the display list
// loses: a non-ASCII name (safe_path-rendered) and a path past the 200-char
// display budget.
const astNonASCIIPath = "src/données/ルート_файл.js"

var astLongPath = "src/" + strings.Repeat("deeply_nested_module_directory/", 8) + "request_handler_for_uploads.ts"

// memoryRecorder is the audit_memories side of the closure pass. It keeps
// every status ever written per fingerprint, because the contract is "never
// synced to resolved", not merely "not resolved at the end".
type memoryRecorder struct {
	mu       sync.Mutex
	statuses map[string][]string
}

func (m *memoryRecorder) SetRemediationStatus(fingerprint, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses[fingerprint] = append(m.statuses[fingerprint], status)
	return nil
}

func (m *memoryRecorder) history(fingerprint string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.statuses[fingerprint]...)
}

// astWorld is newLineageStack's repository with the §8 memory sync wired, so
// the `remediation_status` half of the contract is observable, over a
// marker-resolved local target. root is canonical: absolute row paths are
// expressed under it.
type astWorld struct {
	t      *testing.T
	svc    service.LineageService
	repo   repository.LineageRepository
	mem    *memoryRecorder
	source *model.Source
	root   string
}

func newASTWorld(t *testing.T) *astWorld {
	t.Helper()
	_, repo := newLineageStack(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("canonical root: %v", err)
	}
	mustWrite(t, filepath.Join(root, "package.json"), "{}\n")
	mem := &memoryRecorder{statuses: map[string][]string{}}
	return &astWorld{
		t: t, svc: service.NewLineageServiceWithMemory(repo, mem), repo: repo, mem: mem,
		source: targetLocalSource("src-ast-guard", root), root: root,
	}
}

// scanned is the source scan 2 stands on: the root, or a sub-path scan of
// <root>/<sub>.
func (w *astWorld) scanned(sub string) *model.Source {
	w.t.Helper()
	if sub == "" {
		return w.source
	}
	dir := filepath.Join(w.root, sub)
	mustMkdirAll(w.t, dir)
	return targetLocalSource("src-ast-guard-sub", dir)
}

// astFinding is a deterministic (skill-tier) finding, as BOTH the AST tier and
// the regex tier emit it: provenance "skill" either way, which is why the
// guard keys on the category.
func astFinding(v2, category, filePath string) model.Finding {
	f := detTargetFinding("v1-"+v2, v2, filePath)
	f.Category = category
	f.Title = "Untrusted input reaches a " + category + " sink"
	return f
}

// astCoverage renders a §10.2-shaped `ast_coverage` object. `fallback_paths`
// is deliberately LOSSY here — '?'-rendered and cut at 40 characters, the way
// safe_path and the 200-cap make it lossy in production — so a guard that
// read the display list instead of `fallback_keys` would miss the files.
func astCoverage(t *testing.T, breaker bool, keys ...string) string {
	t.Helper()
	if keys == nil {
		keys = []string{} // `[]`, never `null`: a null fallback_keys is malformed and holds
	}
	display := make([]string, 0, len(keys))
	for _, k := range keys {
		display = append(display, lossyDisplay(k))
	}
	raw, err := json.Marshal(map[string]any{
		"grammars": map[string]string{"javascript": "0.25.0"},
		"files": map[string]any{
			"parsed":                   3,
			"fallback":                 map[string]int{"parse_error": len(keys), "circuit_open": 0},
			"fallback_paths":           display,
			"fallback_paths_truncated": false,
			"fallback_keys":            keys,
			"breaker_tripped":          breaker,
		},
		"workers": map[string]any{"count": 1, "recycled": 0, "breaker_tripped": breaker},
	})
	if err != nil {
		t.Fatalf("marshal ast_coverage: %v", err)
	}
	return string(raw)
}

func lossyDisplay(key string) string {
	out := []rune(strings.Map(func(r rune) rune {
		if r > 0x7e {
			return '?'
		}
		return r
	}, key))
	if len(out) > 40 {
		out = append(out[:39], '…')
	}
	return string(out)
}

// astResult builds the agent's result exactly as the stream handler does: the
// snapshot bytes through agui.ParseScanOutcome, then the agent's findings.
// astCov == "" means the key is ABSENT (an agent without the AST layer).
//
// The envelope check is load-bearing: a malformed `ast_coverage` must cost the
// guard, never the 0091 scope keys beside it.
func astResult(t *testing.T, astCov string, findings ...model.Finding) *model.ScanResult {
	t.Helper()
	payload := `{"result_schema":2,"pruned_dirs":[],"findings":[]`
	if astCov != "" {
		payload += `,"ast_coverage":` + astCov
	}
	payload += `}`
	result := agui.ParseScanOutcome(json.RawMessage(payload))
	if !result.HasEvidenceProtocol() {
		t.Fatalf("an `ast_coverage` value must not cost the result envelope: "+
			"result_schema lost for payload %s", payload)
	}
	result.Findings = findings
	return result
}

// record is one scan by `agent` reporting exactly `findings`.
func (w *astWorld) record(source *model.Source, auditID, agent, astCov string, findings ...model.Finding) {
	w.t.Helper()
	if err := w.svc.RecordScanOutcome(lineageTestAudit(auditID), source, agent,
		astResult(w.t, astCov, findings...)); err != nil {
		w.t.Fatalf("%s: %v", auditID, err)
	}
}

// seed is scan 1: the AST tier parsed everything and reported the findings,
// so each becomes an `open` row. It returns row ids keyed by fingerprint_v2.
func (w *astWorld) seed(agent string, findings ...model.Finding) map[string]string {
	w.t.Helper()
	w.record(w.source, "audit-ast-1", agent, astCoverage(w.t, false), findings...)
	rows := lineageRowsAcross(w.t, w.repo, w.source.Path)
	ids := make(map[string]string, len(rows))
	for _, r := range rows {
		ids[r.FingerprintV2] = r.ID
	}
	for _, f := range findings {
		if ids[f.FingerprintV2] == "" {
			w.t.Fatalf("scan 1 must create a row for %s, got:%s", f.FingerprintV2, summarizeRows(rows))
		}
	}
	return ids
}

// rescan is scan N: the agent reports `findings` plus noise — a result
// carrying nothing at all for an agent closes nothing (see targetNoise) — and
// the given ast_coverage.
func (w *astWorld) rescan(source *model.Source, auditID, agent, astCov string, findings ...model.Finding) {
	w.t.Helper()
	noise := targetNoise("v1-noise-" + agent)
	noise.AgentType = agent
	w.record(source, auditID, agent, astCov, append(findings, noise)...)
}

// assertHeld is the D24 contract for one row: `unconfirmed`, no `fixed`
// transition on its timeline, a reasoned `unconfirmable` event, and no memory
// sync to `resolved`.
func (w *astWorld) assertHeld(id, why string) {
	w.t.Helper()
	row := reloadLineage(w.t, w.repo, id)
	if row.CurrentStatus != model.LineageStatusUnconfirmed {
		w.t.Fatalf("%s: a %s row on a file the AST tier did not own this scan must be held %q, "+
			"never closed — got %q (file %q)", why, row.Category, model.LineageStatusUnconfirmed,
			row.CurrentStatus, row.FilePath)
	}
	w.assertHeldTimeline(id, why)
	if hist := w.mem.history(row.Fingerprint); slices.Contains(hist, "resolved") {
		w.t.Fatalf("%s: audit_memories.remediation_status was synced to %q for a held row "+
			"(history %v) — the next scan's prior-findings block would tell the model to skip "+
			"a still-present vulnerability", why, "resolved", hist)
	}
}

// assertHeldTimeline: a held row never carries a `fixed` transition, and its
// timeline records WHY it was held.
func (w *astWorld) assertHeldTimeline(id, why string) {
	w.t.Helper()
	if hasEvent(w.t, w.repo, id, model.LineageEventFixed) {
		w.t.Fatalf("%s: a held row must never carry a %q transition, got %v",
			why, model.LineageEventFixed, eventTypesOf(w.t, w.repo, id))
	}
	noted := func(n string) bool { return strings.TrimSpace(n) != "" }
	if !slices.ContainsFunc(unconfirmableNotes(w.t, w.repo, id), noted) {
		w.t.Fatalf("%s: the timeline must record WHY the row was held (an %q event with a note), got %v",
			why, model.LineageEventUnconfirmable, eventTypesOf(w.t, w.repo, id))
	}
}

// assertClosed is the CONTROL: today's deterministic closure, unchanged.
func (w *astWorld) assertClosed(id, why string) {
	w.t.Helper()
	row := reloadLineage(w.t, w.repo, id)
	if row.CurrentStatus != model.LineageStatusFixed {
		w.t.Fatalf("control (%s): a deterministic %s row absent from an in-scope scan still closes "+
			"as %q, got %q (file %q) — the guard must not become 'stop closing anything'",
			why, row.Category, model.LineageStatusFixed, row.CurrentStatus, row.FilePath)
	}
	hist := w.mem.history(row.Fingerprint)
	if len(hist) == 0 || hist[len(hist)-1] != "resolved" {
		w.t.Fatalf("control (%s): a closed row syncs audit_memories to %q, history %v", why, "resolved", hist)
	}
}

// astRow is one tracked row of a table case and what scan 2 must do to it.
type astRow struct {
	v2, category, path string
	abs                bool // stored under its ABSOLUTE path <root>/<path>
	held               bool // held `unconfirmed`; false = a CONTROL that closes `fixed`
}

// astCase is scan 1 (every row reported, the AST tier parsed everything)
// followed by scan 2 (no row re-reported) carrying `cov`.
type astCase struct {
	name string
	cov  string // scan 2's ast_coverage; "" = ABSENT
	sub  string // scan 2 is a sub-path scan of <root>/<sub>; "" = the root
	rows []astRow
}

// TestASTGuardHoldsOrClosesEachRow is the D24 decision row by row: every case
// holds what the contract holds and closes its controls as today.
func TestASTGuardHoldsOrClosesEachRow(t *testing.T) {
	if len(astLongPath) <= 200 {
		t.Fatalf("precondition: the long path must exceed 200 characters, got %d", len(astLongPath))
	}
	// A PRESENT ast_coverage the backend cannot read is not an absent one: it
	// says the AST layer ran and some file state exists the backend could not
	// decode. The owned row sits on a file the payload does not (readably)
	// name, so only hold-all can hold it; the CWE-79 control still closes —
	// the guard stays scoped to the AST-owned categories.
	malformed := []astRow{
		{v2: "v2-bad-22", category: "CWE-22", path: astParsedFile, held: true},
		{v2: "v2-bad-79", category: "CWE-79", path: astParsedFile},
	}
	cases := []astCase{
		// The D24 pin: the file fell back (parse_error) and nothing was
		// reported on it. Every AST-owned category is held; a CWE-79 row says
		// nothing to the AST tier, and a CWE-22 row on a file NOT in
		// fallback_keys was really re-read, so both close.
		{name: "parse_error file holds every owned category", cov: astCoverage(t, false, astFallbackFile), rows: []astRow{
			{v2: "v2-ast-22", category: "CWE-22", path: astFallbackFile, held: true},
			{v2: "v2-ast-918", category: "CWE-918", path: astFallbackFile, held: true},
			{v2: "v2-ast-78", category: "CWE-78", path: astFallbackFile, held: true},
			{v2: "v2-ast-79", category: "CWE-79", path: astFallbackFile},
			{v2: "v2-ast-22-parsed", category: "CWE-22", path: astParsedFile},
		}},
		// fallback_keys carries the display list's two lossy shapes
		// losslessly, and that is the set the guard reads.
		{name: "non-ASCII and over-200-char keys", cov: astCoverage(t, false, astNonASCIIPath, astLongPath), rows: []astRow{
			{v2: "v2-ast-nonascii", category: "CWE-22", path: astNonASCIIPath, held: true},
			{v2: "v2-ast-long", category: "CWE-78", path: astLongPath, held: true},
		}},
		// ~77% of deterministic rows store an ABSOLUTE file_path while
		// fallback_keys are root-relative: the guard normalises the row first,
		// or exactly the common row shape falls through and closes.
		{name: "absolute-path prior row", cov: astCoverage(t, false, "src/handlers/download.js"), rows: []astRow{
			{v2: "v2-ast-abs", category: "CWE-22", path: "src/handlers/download.js", abs: true, held: true},
			{v2: "v2-ast-abs-reread", category: "CWE-22", path: "src/handlers/ok.js", abs: true},
		}},
		// The circuit_open mass case: after the breaker trips every remaining
		// file is regex-owned, so no AST-owned row closes on absence — even on
		// files not (or not yet) in fallback_keys. Only src/a.js is listed.
		{name: "breaker_tripped holds every owned row", cov: astCoverage(t, true, "src/a.js"), rows: []astRow{
			{v2: "v2-brk-22", category: "CWE-22", path: "src/a.js", held: true},
			{v2: "v2-brk-918", category: "CWE-918", path: "src/b.ts", held: true},
			{v2: "v2-brk-78", category: "CWE-78", path: "lib/c.py", held: true},
			{v2: "v2-brk-79", category: "CWE-79", path: "src/a.js"},
		}},
		// An older agent, or a skills run of an agent without the AST layer,
		// sends no ast_coverage: no guard, today's closure.
		{name: "absent ast_coverage keeps today's closure", rows: []astRow{
			{v2: "v2-absent-22", category: "CWE-22", path: astFallbackFile},
		}},
		{name: "malformed: fallback_keys not a list", cov: `{"files":{"fallback_keys":"src/routes/files.js","breaker_tripped":false}}`, rows: malformed},
		{name: "malformed: fallback_keys element not text", cov: `{"files":{"fallback_keys":[42],"breaker_tripped":false}}`, rows: malformed},
		{name: "malformed: fallback_keys missing", cov: `{"files":{"parsed":3,"breaker_tripped":false}}`, rows: malformed},
		{name: "malformed: breaker_tripped not a bool", cov: `{"files":{"fallback_keys":[],"breaker_tripped":"no"}}`, rows: malformed},
		{name: "malformed: files not an object", cov: `{"files":["src/routes/files.js"]}`, rows: malformed},
		{name: "malformed: ast_coverage not an object", cov: `"degraded"`, rows: malformed},
		// Like pruned_dirs, fallback_keys are relative to the directory the
		// agent WALKED: a sub-path scan of <root>/svc reports `handler.js` for
		// the row at `svc/handler.js`. Both must meet in target coordinates.
		{name: "sub-path scan keys are in scan coordinates", cov: astCoverage(t, false, "handler.js"), sub: "svc", rows: []astRow{
			{v2: "v2-sub-918", category: "CWE-918", path: "svc/handler.js", held: true},
			{v2: "v2-sub-918-reread", category: "CWE-918", path: "svc/other.js"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { runASTCase(t, tc) })
	}
}

func runASTCase(t *testing.T, tc astCase) {
	t.Helper()
	w := newASTWorld(t)
	ids := w.seedRows(tc.rows)
	w.rescan(w.scanned(tc.sub), "audit-ast-2", "cwe", tc.cov)
	for i, r := range tc.rows {
		if r.held {
			w.assertHeld(ids[i], tc.name)
			continue
		}
		w.assertClosed(ids[i], tc.name)
	}
}

// seedRows seeds a case's rows (cwe agent) and returns their ids in order.
func (w *astWorld) seedRows(rows []astRow) []string {
	w.t.Helper()
	findings := make([]model.Finding, len(rows))
	for i, r := range rows {
		findings[i] = astFinding(r.v2, r.category, w.rowPath(r))
	}
	byV2 := w.seed("cwe", findings...)
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = byV2[r.v2]
		w.requireStoredAbsolute(r, ids[i])
	}
	return ids
}

func (w *astWorld) rowPath(r astRow) string {
	if r.abs {
		return filepath.Join(w.root, filepath.FromSlash(r.path))
	}
	return r.path
}

// requireStoredAbsolute is the absolute-path precondition: the prior row
// really is stored ABSOLUTE, so the guard has to place it.
func (w *astWorld) requireStoredAbsolute(r astRow, id string) {
	w.t.Helper()
	if !r.abs {
		return
	}
	if stored := reloadLineage(w.t, w.repo, id).FilePath; !filepath.IsAbs(stored) {
		w.t.Fatalf("precondition: the prior row must be stored with an ABSOLUTE path, got %q", stored)
	}
}

// TestASTHeldRowIsNotFrozen: the hold lasts exactly as long as the fallback.
// Once the file parses again the AST tier owns it: a re-report settles the row
// back to `open`, and a later absence closes it as fixed — so an over-hold is
// recoverable and the guard never freezes a row forever.
func TestASTHeldRowIsNotFrozen(t *testing.T) {
	w := newASTWorld(t)
	f := astFinding("v2-recover-78", "CWE-78", astFallbackFile)
	id := w.seed("cwe", f)[f.FingerprintV2]

	w.rescan(w.source, "audit-ast-2", "cwe", astCoverage(t, false, astFallbackFile))
	w.assertHeld(id, "scan 2: parse_error")

	w.rescan(w.source, "audit-ast-3", "cwe", astCoverage(t, false), f)
	if got := reloadLineage(t, w.repo, id).CurrentStatus; got != model.LineageStatusOpen {
		t.Fatalf("scan 3: the file parsed again and the AST tier re-reported the finding, so the "+
			"held row settles back to %q, got %q", model.LineageStatusOpen, got)
	}

	w.rescan(w.source, "audit-ast-4", "cwe", astCoverage(t, false))
	w.assertClosed(id, "scan 4: the file parsed and the finding is gone")
}

// TestASTGuardIsKeyedByTheClosingAgent: the cwe agent's ast_coverage speaks
// only for the cwe agent's rows. Another agent's pass reads its OWN result;
// with no ast_coverage there, its owned-category row on the same file closes
// as today, while the cwe row is held.
func TestASTGuardIsKeyedByTheClosingAgent(t *testing.T) {
	w := newASTWorld(t)
	cweRow := astFinding("v2-agent-cwe-22", "CWE-22", astFallbackFile)
	other := astFinding("v2-agent-asvs-22", "CWE-22", astFallbackFile)
	other.AgentType = "asvs"
	other.Title = "Path traversal (ASVS V12)"
	cweID := w.seed("cwe", cweRow)[cweRow.FingerprintV2]
	asvsID := w.seed("asvs", other)[other.FingerprintV2]

	w.rescan(w.source, "audit-ast-2", "cwe", astCoverage(t, false, astFallbackFile))
	w.rescan(w.source, "audit-ast-2", "asvs", "")

	w.assertHeld(cweID, "the cwe agent's own fallback file")
	w.assertClosed(asvsID, "another agent's row is governed by that agent's result, which carries no ast_coverage")
}
