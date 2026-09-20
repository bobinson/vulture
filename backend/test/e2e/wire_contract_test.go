//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 — THE CONTRACT SEAM BETWEEN THE API AND THE UI.
//
// THE DEFECT CLASS THIS FILE EXISTS FOR. P4 (the Go endpoints) and P5 (the
// React pages) were written in parallel against a written contract — LLD §10.1
// — and each was verified against its OWN tests. The Go E2E drives the real
// endpoints; the Playwright E2E drives the real pages against a MOCK of those
// endpoints. Both suites can be green while the feature is dead in production,
// because nothing runs the two halves against EACH OTHER: the mock is written
// from the same prose the handler was, so a field the handler never sends is
// present in the mock and the UI test passes on data the server will never
// produce.
//
// That is not hypothetical. It is the third occurrence of one shape in this
// feature:
//
//	P1 — the agent request model silently dropped a new field (Pydantic), so
//	     the mechanism shipped inert.
//	P3 — the migration's `target_key` and the runtime's `target_key` were
//	     different namespaces, so after the backfill the first scan matched
//	     none of the 10,663 rows.
//	P4/P5 — `GET /api/audits/{id}` never sent `target_key`, which
//	     `AuditResults.tsx` reads to drive the scan-history rail and the only
//	     link from a scan to its codebase. `auditPayload()` in
//	     target-aggregate-default.spec.ts supplies it, so Playwright was green
//	     while the rail was invisible on every real page load.
//
// The two tests below close that seam from both directions:
//
//	TestAuditCarriesTargetKeyForScanRail is BEHAVIOURAL. It walks the actual
//	drill-down the user performs — audit -> target key -> that target's scans —
//	over real HTTP. A field rename anywhere on that path breaks the walk, and
//	no mock can make it pass.
//
//	TestWireShapeMatchesFrontendTypes is STRUCTURAL. It reads the REAL JSON off
//	the wire and diffs its key set against the field names declared in
//	frontend/src/lib/types.ts — the file the components are written against.
//	A snake_case/camelCase slip, a nested object the UI expects flat, or a
//	required field the API never sends all surface here as a named difference
//	rather than as an empty pane in a browser.

// ─────────────────────────────────────────────────────────────────────────────
// 1. Behavioural: the /audit/{id} -> codebase drill-down.
// ─────────────────────────────────────────────────────────────────────────────

// TestAuditCarriesTargetKeyForScanRail pins the path the per-scan results page
// takes to render its scan-history rail and its "all findings for this
// codebase" link (LLD §10.2).
//
// AuditResults.tsx does exactly this:
//
//	const { scans } = useAuditHistory(audit?.target_key)   // -> /api/targets/{key}/scans
//	<ScanHistoryRail scans={scans} targetKey={audit?.target_key} />
//
// `useTargetScans(undefined)` never fires a request and ScanHistoryRail returns
// null for an empty list, so an absent `target_key` does not error — it renders
// NOTHING, on every scan page, for ever. That silence is why this has to be a
// test and not a review.
func TestAuditCarriesTargetKeyForScanRail(t *testing.T) {
	w := newAggWorld(t)
	tgt := w.target("blu-simulator")
	base := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	w.scan(tgt, "aud-root", "", "main", base, "cwe")
	w.scan(tgt, "aud-vscode", ".vscode", "main", base.Add(time.Hour), "cwe")
	w.row(aggSeed{
		Label: "rail", Target: tgt, Audit: "aud-root", Status: model.LineageStatusOpen,
		Severity: model.SeverityCritical, Category: "CWE-506", RelPath: ".vscode/tasks.json",
		Line: 7, Provenance: "llm", SeenCount: 2, At: base,
	})
	w.serve()

	// Step 1 — the page loads its audit. This is the read that was silently
	// missing `target_key`.
	var audit struct {
		ID        string `json:"id"`
		TargetKey string `json:"target_key"`
	}
	aggGet(t, w.addr, "/api/audits/aud-root", &audit)
	if audit.TargetKey == "" {
		t.Fatalf("GET /api/audits/aud-root carries no `target_key`.\n"+
			"AuditResults.tsx reads audit.target_key to drive useAuditHistory() and the "+
			"ScanHistoryRail link; with it undefined the hook never fetches, the rail "+
			"renders null, and there is NO route from a scan to its codebase report. "+
			"Populate model.Audit.TargetKey from sources.target_key in BOTH "+
			"PostgresRepo.GetAudit and SQLiteRepo.GetAudit.\ngot audit: %+v", audit)
	}

	// Step 2 — the key the audit reports must be the key the target list uses.
	// A key that is merely non-empty is not enough: if the two are computed in
	// different namespaces the rail requests a target that does not exist and
	// renders empty, which looks identical to the bug above (this is the P3
	// failure, repeated one layer up).
	var targets []aggTargetRow
	aggGet(t, w.addr, "/api/targets", &targets)
	found := false
	keys := make([]string, 0, len(targets))
	for _, tr := range targets {
		keys = append(keys, tr.TargetKey)
		if tr.TargetKey == audit.TargetKey {
			found = true
		}
	}
	if !found {
		t.Fatalf("the audit's target_key %q matches no target in GET /api/targets %q.\n"+
			"sources.target_key and finding_lineage.target_key must be the SAME namespace "+
			"(both are service.ResolveTarget(...).Key); if they diverge the rail requests a "+
			"target that does not exist and renders empty.", audit.TargetKey, keys)
	}

	// Step 3 — that key must actually resolve to this scan's history, including
	// the sub-path scan, which is the whole reason the rail is keyed by target
	// rather than by source path (§7.2).
	var scans []aggScanRow
	aggGet(t, w.addr, "/api/targets/"+escapePathSegment(audit.TargetKey)+"/scans", &scans)
	got := map[string]bool{}
	for _, s := range scans {
		got[s.AuditID] = true
	}
	for _, want := range []string{"aud-root", "aud-vscode"} {
		if !got[want] {
			t.Fatalf("GET /api/targets/%s/scans omits %q; the rail on /audit/%s would not "+
				"show it. A root scan and a sub-path scan of one codebase are the SAME "+
				"target (§7.2). got: %v", audit.TargetKey, want, want, got)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Structural: the real JSON against frontend/src/lib/types.ts.
// ─────────────────────────────────────────────────────────────────────────────

// TestWireShapeMatchesFrontendTypes diffs the key set of every 0091 response
// against the interface the frontend renders it with.
//
// Two rules, and they catch opposite mistakes:
//
//	UNDECLARED KEY — the API sends something types.ts does not declare. Either
//	the UI is silently ignoring data it was meant to show, or the field was
//	renamed on one side only.
//
//	MISSING REQUIRED FIELD — types.ts declares a field WITHOUT `?` and the API
//	does not send it. The component reads `undefined` and renders a blank cell,
//	"NaN", or nothing at all — no error anywhere.
//
// An optional (`?`) field absent from the payload is fine: that is exactly what
// Go's `omitempty` means, and the UI is written to handle it.
func TestWireShapeMatchesFrontendTypes(t *testing.T) {
	types := loadFrontendTypes(t)

	w := newAggWorld(t)
	tgt := w.target("blu-simulator")
	base := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	w.scan(tgt, "aud-1", "", "main", base, "cwe")
	w.scan(tgt, "aud-2", ".vscode", "main", base.Add(time.Hour), "cwe")
	l := w.row(aggSeed{
		Label: "shape", Target: tgt, Audit: "aud-1", Status: model.LineageStatusOpen,
		Severity: model.SeverityCritical, Category: "CWE-506", RelPath: ".vscode/tasks.json",
		Line: 7, Provenance: "llm", SeenCount: 2, At: base,
	})
	w.event(l.ID, model.LineageEventConfirmedByEvidence, "aud-2", "quote still present",
		base.Add(time.Hour))
	w.serve()

	key := escapePathSegment(tgt.Key)

	// GET /api/targets -> TargetSummary[]
	checkObjects(t, types, "TargetSummary", "GET /api/targets",
		firstObjects(t, w, "/api/targets"))

	// GET /api/targets/{key}/scans -> TargetScan[]
	checkObjects(t, types, "TargetScan", "GET /api/targets/{key}/scans",
		firstObjects(t, w, "/api/targets/"+key+"/scans"))

	// GET /api/targets/{key}/aggregate -> AggregateResponse
	report := firstObject(t, w, aggregateURL(tgt.Key, "status=all"))
	checkObjects(t, types, "AggregateResponse", "GET .../aggregate", []map[string]any{report})
	checkObjects(t, types, "AggregateTiles", "GET .../aggregate > tiles",
		[]map[string]any{nestedObject(t, report, "tiles")})
	checkObjects(t, types, "AggregateRow", "GET .../aggregate > rows[]",
		nestedArray(t, report, "rows"))

	// GET /api/lineage/{id} -> { lineage, events, evidence, seen_in }
	detail := firstObject(t, w, "/api/lineage/"+l.ID)
	for _, want := range []string{"lineage", "events", "evidence", "seen_in"} {
		if _, ok := detail[want]; !ok {
			t.Errorf("GET /api/lineage/{id}: response has no %q key. lib/lineage.ts "+
				"normalizeLineageDetail() flattens exactly {lineage, events, evidence, "+
				"seen_in}; a key it cannot find is a field the detail page never renders. "+
				"got keys: %v", want, sortedJSONKeys(detail))
		}
	}
	checkObjects(t, types, "LineageEvidence", "GET /api/lineage/{id} > evidence",
		[]map[string]any{nestedObject(t, detail, "evidence")})
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers.
// ─────────────────────────────────────────────────────────────────────────────

// tsField is one declared property of a TypeScript interface.
type tsField struct {
	name     string
	optional bool
}

// checkObjects applies both rules to every object a response yielded. Every
// object of a list is checked, not just the first: `omitempty` means two rows
// of one list can have different key sets, and the row that omits a required
// field is the one that breaks the page.
func checkObjects(t *testing.T, types map[string][]tsField, iface, where string, objs []map[string]any) {
	t.Helper()
	fields, ok := types[iface]
	if !ok {
		t.Fatalf("frontend/src/lib/types.ts declares no `export interface %s`; the wire "+
			"contract for %s has no counterpart the UI is written against", iface, where)
	}
	if len(objs) == 0 {
		t.Fatalf("%s returned no object to check against %s — the fixture must produce at "+
			"least one, or this test passes vacuously", where, iface)
	}
	declared := map[string]tsField{}
	for _, f := range fields {
		declared[f.name] = f
	}
	for i, obj := range objs {
		for _, k := range sortedJSONKeys(obj) {
			if _, ok := declared[k]; !ok {
				t.Errorf("%s [%d]: sends %q, which `interface %s` does not declare.\n"+
					"Either the UI is silently dropping this field or it was renamed on one "+
					"side only. Declared: %v", where, i, k, iface, fieldNames(fields))
			}
		}
		for _, f := range fields {
			if f.optional {
				continue
			}
			if _, ok := obj[f.name]; !ok {
				t.Errorf("%s [%d]: `interface %s` declares %q as REQUIRED (no `?`) but the "+
					"API never sends it.\nThe component reads undefined and renders nothing "+
					"— silently. Either send the field or mark it optional in types.ts.\n"+
					"sent keys: %v", where, i, iface, f.name, sortedJSONKeys(obj))
			}
		}
	}
}

// loadFrontendTypes parses every `export interface` in frontend/src/lib/types.ts.
func loadFrontendTypes(t *testing.T) map[string][]tsField {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this test file to find the frontend sources")
	}
	path := filepath.Join(filepath.Dir(self), "..", "..", "..", "frontend", "src", "lib", "types.ts")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("frontend/src/lib/types.ts is not present (%v); the UI half of the contract "+
			"cannot be checked from this checkout", err)
	}
	return parseTSInterfaces(string(src))
}

var (
	tsIfaceRe = regexp.MustCompile(`(?m)^export interface ([A-Za-z0-9_]+)\s*\{`)
	tsFieldRe = regexp.MustCompile(`^([a-z_][A-Za-z0-9_]*)(\??)\s*:`)
)

// parseTSInterfaces pulls the top-level property names out of each interface.
//
// It tracks brace depth so a nested object literal or a generic like
// `Record<string, unknown>` cannot contribute phantom fields, and it strips
// comments first so a field name mentioned in prose is not mistaken for a
// declaration.
func parseTSInterfaces(src string) map[string][]tsField {
	out := map[string][]tsField{}
	for _, loc := range tsIfaceRe.FindAllStringSubmatchIndex(src, -1) {
		name := src[loc[2]:loc[3]]
		body := src[loc[1]:]
		depth := 1
		var fields []tsField
		for _, raw := range strings.Split(body, "\n") {
			line := stripTSComment(raw)
			if depth == 1 {
				if m := tsFieldRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
					fields = append(fields, tsField{name: m[1], optional: m[2] == "?"})
				}
			}
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth <= 0 {
				break
			}
		}
		out[name] = fields
	}
	return out
}

// stripTSComment removes a `//` tail and any `/* … */` span on the line, so
// commentary never parses as a declaration.
func stripTSComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		line = line[:i]
	}
	for {
		start := strings.Index(line, "/*")
		if start < 0 {
			break
		}
		end := strings.Index(line[start:], "*/")
		if end < 0 {
			return line[:start]
		}
		line = line[:start] + line[start+end+2:]
	}
	// A doc-comment continuation line (` * text`) is prose, never a field.
	if strings.HasPrefix(strings.TrimSpace(line), "*") {
		return ""
	}
	return line
}

// firstObjects decodes a JSON array response into generic maps.
func firstObjects(t *testing.T, w *aggWorld, path string) []map[string]any {
	t.Helper()
	var raw []map[string]any
	aggGet(t, w.addr, path, &raw)
	return raw
}

// firstObject decodes a JSON object response into a generic map.
func firstObject(t *testing.T, w *aggWorld, path string) map[string]any {
	t.Helper()
	var raw map[string]any
	aggGet(t, w.addr, path, &raw)
	return raw
}

func nestedObject(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	obj, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("expected %q to be a JSON object, got %T (%v)", key, parent[key], parent[key])
	}
	return obj
}

func nestedArray(t *testing.T, parent map[string]any, key string) []map[string]any {
	t.Helper()
	list, ok := parent[key].([]any)
	if !ok {
		t.Fatalf("expected %q to be a JSON array, got %T", key, parent[key])
	}
	out := make([]map[string]any, 0, len(list))
	for i, item := range list {
		obj, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("%s[%d] is %T, not an object", key, i, item)
		}
		out = append(out, obj)
	}
	return out
}

func sortedJSONKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func fieldNames(fields []tsField) []string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f.optional {
			out = append(out, f.name+"?")
			continue
		}
		out = append(out, f.name)
	}
	return out
}

// escapePathSegment encodes a target key the way the frontend's
// encodeURIComponent does — every reserved character, `/` and `:` included,
// so a `git:github.com/acme/repo` key stays ONE path segment.
func escapePathSegment(key string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
	var b strings.Builder
	for i := 0; i < len(key); i++ {
		c := key[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		const hex = "0123456789ABCDEF"
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

// compile-time proof the helpers above are used with encoding/json semantics.
var _ = json.Marshal
