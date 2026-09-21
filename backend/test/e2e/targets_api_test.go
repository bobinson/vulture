//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

// Feature 0091 P4 — THE TARGETS API AND THE AGGREGATE REPORT.
//
// THE DEFECT THESE TESTS PIN. Everything the product can show you today is
// scoped to ONE audit: `/api/audits/{id}` is one scan's findings and
// `/api/audits/{id}/comparison` is one scan against its predecessor. There is
// no endpoint that answers the question a user actually has —
//
//	"what has this codebase ever been told about itself, and what is still true?"
//
// and no endpoint scoped to a CODEBASE at all. P3 built the identity that makes
// that question answerable (`target_key`, `fingerprint_v2`, `seen_count`,
// `merged_into`, a widened status vocabulary). P4 is the read side.
//
// FOUR PROPERTIES THE READ SIDE HAS TO HAVE, each of which is a way this
// endpoint can be built wrong while looking right:
//
//  1. EVERY ISSUE EVER REPORTED IS REACHABLE. A finding that was closed —
//     `fixed` by a scan, or `resolved` / `false_positive` / `accepted_risk` by a
//     human — is not deleted history. `status=all` must surface all four
//     terminal states; the default `active` view must surface none of them and
//     must still surface `unconfirmed` and `regression`, which are ACTIVE
//     (model.ActiveLineageStatuses) and are the two states a naive
//     `status = 'open'` filter silently drops.
//
//  2. A ROW IS A FINDING, NOT AN OCCURRENCE. The whole point of lineage is that
//     one finding seen in five scans is ONE thing with a history. An
//     implementation that joins per scan returns it five times, and the "40
//     unique findings" headline becomes a scan-count multiplied by a
//     finding-count.
//
//  3. THE MERGE STAYS MERGED. Migration 027 retired duplicate rows by setting
//     `merged_into` rather than deleting them, so a stale VLT link still leads
//     somewhere. A report that forgets the clause resurrects every duplicate
//     the migration retired — and double-counts it in the tiles.
//
//  4. IT DOES NOT TOUCH `findings`. The aggregate is computed from
//     `finding_lineage` ALONE. `findings` holds 93,341 rows against
//     finding_lineage's 10,663, and the join is the difference between a report
//     that opens and one that times out. This is a STRUCTURAL property, not a
//     performance target: timing on a seeded test DB would pass with the join
//     present, so TestAggregateNoJoinToFindings reads the SQL instead.
//
// Everything here is driven over HTTP against the real server, because the
// contract being pinned is the wire shape in LLD §10.1 — field names included.
// The frontend (P5) is written against these exact keys, so a rename here is a
// silent breakage there.

// ─────────────────────────────────────────────────────────────────────────────
// Wire shapes — LLD §10.1. These structs ARE the contract; a field renamed in
// the handler shows up here as a zero value, which every assertion below reads
// as a failure.
// ─────────────────────────────────────────────────────────────────────────────

// aggTargetRow is one entry of GET /api/targets.
type aggTargetRow struct {
	TargetKey        string `json:"target_key"`
	DisplayName      string `json:"display_name"`
	ScanCount        int    `json:"scan_count"`
	ActiveCount      int    `json:"active_count"`
	UnconfirmedCount int    `json:"unconfirmed_count"`
	FixedCount       int    `json:"fixed_count"`
	LastScanAt       string `json:"last_scan_at"`
	LastAuditID      string `json:"last_audit_id"`
}

// aggScanRow is one entry of GET /api/targets/{key}/scans.
type aggScanRow struct {
	AuditID   string   `json:"audit_id"`
	CreatedAt string   `json:"created_at"`
	SubPath   string   `json:"sub_path"`
	GitBranch string   `json:"git_branch"`
	DetCount  int      `json:"det_count"`
	LLMCount  int      `json:"llm_count"`
	Types     []string `json:"types"`
}

// aggReportRow is one unique finding in GET /api/targets/{key}/aggregate.
type aggReportRow struct {
	LineageID   string `json:"lineage_id"`
	Ref         string `json:"ref"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	RelPath     string `json:"rel_path"`
	LineStart   int    `json:"line_start"`
	Tier        string `json:"tier"`
	SeenCount   int    `json:"seen_count"`
	ScanCount   int    `json:"scan_count"`
	Status      string `json:"status"`
	FirstSeenAt string `json:"first_seen_at"`
	LastSeenAt  string `json:"last_seen_at"`
	LastEvent   string `json:"last_event"`
}

// aggTiles is the headline strip above the table.
//
// The tiles describe the TARGET (within the selected `scans`), not the filtered
// row set, and that is load-bearing rather than incidental: under the default
// `status=active` view the `fixed` tile is the ONLY thing on the page telling a
// user that closed findings exist and are one click away. A tile that moved
// with the status filter would read 0 in exactly the view where it matters, and
// property (1) above would have no signpost.
type aggTiles struct {
	Unique      int `json:"unique"`
	Active      int `json:"active"`
	Unconfirmed int `json:"unconfirmed"`
	Fixed       int `json:"fixed"`
	Critical    int `json:"critical"`
}

// aggResponse is the whole aggregate payload.
type aggResponse struct {
	Total    int             `json:"total"`
	Page     int             `json:"page"`
	PageSize int             `json:"page_size"`
	Tiles    *aggTiles       `json:"tiles"`
	Rows     []aggReportRow  `json:"rows"`
	Raw      json.RawMessage `json:"-"`
}

// aggEvidence is the block GET /api/lineage/{id} gains (LLD §10.1).
type aggEvidence struct {
	LastOutcome string `json:"last_outcome"`
	Reason      string `json:"reason"`
	LineStart   int    `json:"line_start"`
	LineEnd     int    `json:"line_end"`
	FileHash    string `json:"file_hash"`
	CheckedAt   string `json:"checked_at"`
}

// aggLineageDetail is the extended detail response. `lineage` and `events` are
// the pre-0091 shape and must survive unchanged — this endpoint is EXTENDED,
// not replaced, and /audit/{id} deep links already read those two keys.
type aggLineageDetail struct {
	Lineage  *model.FindingLineage `json:"lineage"`
	Events   []model.LineageEvent  `json:"events"`
	Evidence *aggEvidence          `json:"evidence"`
	SeenIn   []string              `json:"seen_in"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture. One `aggWorld` is one isolated backend: its own SQLite file, its own
// scan roots on disk, and the server that reads them.
//
// Seeding happens through the repository BEFORE the server starts and the
// seeding handle is closed first, so two connections never race the idempotent
// migrate() on the same file.
// ─────────────────────────────────────────────────────────────────────────────

type aggWorld struct {
	t       *testing.T
	tmp     string
	dbPath  string
	base    *repository.SQLiteRepo
	lineage repository.LineageRepository
	svc     service.LineageService
	sources map[string]*model.Source // audit id -> the source that scan ran on
	labels  map[string]string        // lineage id -> the seed label, for readable failures
	ids     map[string]string        // seed label -> lineage id
	addr    string
}

// aggTarget is one codebase: a real directory carrying a scan-root marker, and
// the `target_key` the production resolver derives from it.
//
// Marker-resolved rather than git-resolved on purpose. A `git:` key embeds the
// remote URL and therefore slashes, and a slash inside a path segment is
// decoded by net/http before any router sees it — a trap that belongs to the
// implementation's choice of routing, not to the contract these tests pin. A
// `marker:<sha1>` key is a single safe path segment either way.
type aggTarget struct {
	Name string
	Root string
	Key  string
}

func newAggWorld(t *testing.T) *aggWorld {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "targets_api_e2e.db")
	base, err := repository.NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("open sqlite repo: %v", err)
	}
	lineageRepo := repository.NewSQLiteLineageRepo(base.DB())
	return &aggWorld{
		t:       t,
		tmp:     t.TempDir(),
		dbPath:  dbPath,
		base:    base,
		lineage: lineageRepo,
		svc:     service.NewLineageService(lineageRepo),
		sources: map[string]*model.Source{},
		labels:  map[string]string{},
		ids:     map[string]string{},
	}
}

// target creates a scan root named `project` and resolves its target key
// through the production resolver, so the key the test puts in the URL is the
// key the ingest path would have written.
func (w *aggWorld) target(project string) aggTarget {
	w.t.Helper()
	root := filepath.Join(w.tmp, project)
	if err := os.MkdirAll(root, 0o755); err != nil {
		w.t.Fatalf("mkdir scan root %q: %v", root, err)
	}
	// package.json is a scanRootMarkers entry (§7.1 step 2) — the same marker
	// blu-simulator, the target of this feature's reference incident, resolves
	// on.
	if err := os.WriteFile(filepath.Join(root, "package.json"),
		[]byte(`{"name":"`+project+`","version":"1.0.0"}`), 0o644); err != nil {
		w.t.Fatalf("write marker in %q: %v", root, err)
	}
	return aggTarget{Name: project, Root: root, Key: w.keyFor(root)}
}

func (w *aggWorld) keyFor(path string) string {
	w.t.Helper()
	key := service.ResolveTarget(&model.Source{Type: model.SourceTypeLocal, Path: path}).Key
	if key == "" {
		w.t.Fatalf("the target resolver produced no key for %q; the fixture cannot address the API", path)
	}
	return key
}

// scan records one scan of a target: the source row the scan ran on and the
// audit row itself. `subPath` is "" for a root scan and e.g. ".vscode" for a
// sub-path scan, which must inherit the root's key (§7.2) — asserted here so a
// fixture mistake cannot be mistaken for an endpoint bug.
func (w *aggWorld) scan(tgt aggTarget, auditID, subPath, branch string, at time.Time, types ...string) *model.Audit {
	w.t.Helper()
	scanPath := tgt.Root
	if subPath != "" {
		scanPath = filepath.Join(tgt.Root, filepath.FromSlash(subPath))
		if err := os.MkdirAll(scanPath, 0o755); err != nil {
			w.t.Fatalf("mkdir sub-path %q: %v", scanPath, err)
		}
	}
	src := &model.Source{
		ID:             "src-" + auditID,
		Type:           model.SourceTypeLocal,
		Path:           scanPath,
		GitBranch:      branch,
		GitCommitShort: "abc1234",
		CreatedAt:      at,
	}
	src.TargetKey = w.keyFor(scanPath)
	if src.TargetKey != tgt.Key {
		w.t.Fatalf("fixture: a scan of %q must inherit the target key of %q (§7.2): got %q, want %q",
			scanPath, tgt.Root, src.TargetKey, tgt.Key)
	}
	if err := w.base.CreateSource(src); err != nil {
		w.t.Fatalf("create source for %s: %v", auditID, err)
	}
	audit := &model.Audit{
		ID: auditID, SourceID: src.ID, Types: types,
		Status: model.AuditStatusCompleted, CreatedAt: at,
	}
	if err := w.base.CreateAudit(audit); err != nil {
		w.t.Fatalf("create audit %s: %v", auditID, err)
	}
	w.sources[auditID] = src
	return audit
}

// aggSeed describes one lineage row to plant. Every field the aggregate is
// supposed to project or filter on is here, so a test reads as a table.
type aggSeed struct {
	Label      string // how failures name this row
	Target     aggTarget
	Audit      string // the scan that first and last saw it
	Status     model.LineageStatus
	Severity   model.Severity
	Category   string
	RelPath    string
	Line       int
	Provenance string // decides the tier via model.TierOf
	SeenCount  int
	At         time.Time
}

// row plants one lineage row and remembers its id under the seed's label.
func (w *aggWorld) row(s aggSeed) *model.FindingLineage {
	w.t.Helper()
	at := s.At
	if at.IsZero() {
		at = time.Now().UTC().Add(-time.Hour)
	}
	at = at.UTC().Truncate(time.Second)
	latest := at
	l := &model.FindingLineage{
		Fingerprint:       "fp-v1-" + s.Label,
		FingerprintV2:     "fp-v2-" + s.Label,
		SourcePath:        s.Target.Root,
		AgentType:         "cwe",
		CurrentStatus:     s.Status,
		FirstAuditID:      s.Audit,
		FirstFoundAt:      at,
		LatestAuditID:     s.Audit,
		LatestFoundAt:     &latest,
		Severity:          string(s.Severity),
		Category:          s.Category,
		Title:             "seeded finding " + s.Label,
		FilePath:          s.RelPath,
		Provenance:        s.Provenance,
		TargetKey:         s.Target.Key,
		GitBranch:         "main",
		SeenCount:         s.SeenCount,
		LastSeenAuditID:   s.Audit,
		EvidenceLineStart: s.Line,
		EvidenceLineEnd:   s.Line,
	}
	if s.Status == model.LineageStatusFixed {
		l.FixedAuditID = s.Audit
		l.FixedAt = &latest
	}
	if err := w.lineage.UpsertLineage(l); err != nil {
		w.t.Fatalf("seed lineage %q: %v", s.Label, err)
	}
	w.labels[l.ID] = s.Label
	w.ids[s.Label] = l.ID
	return l
}

// event plants one lineage event. CreatedAt is explicit because SQLite stores
// it at RFC3339 second precision, so two events added in the same instant tie
// and "the most recent event" stops being defined.
func (w *aggWorld) event(lineageID string, kind model.LineageEventType, auditID, notes string, at time.Time) {
	w.t.Helper()
	if err := w.lineage.AddEvent(&model.LineageEvent{
		LineageID: lineageID, EventType: kind, AuditID: auditID,
		Notes: notes, CreatedAt: at.UTC().Truncate(time.Second),
	}); err != nil {
		w.t.Fatalf("seed event %s on %s: %v", kind, lineageID, err)
	}
}

// serve closes the seeding handle and starts the server on the seeded database.
func (w *aggWorld) serve() {
	w.t.Helper()
	if err := w.base.Close(); err != nil {
		w.t.Fatalf("close seeding handle: %v", err)
	}
	cfg := testConfig(w.t)
	cfg.DBPath = w.dbPath
	addr, cleanup := startTestServer(w.t, cfg)
	w.t.Cleanup(cleanup)
	w.addr = addr
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP helpers.
// ─────────────────────────────────────────────────────────────────────────────

// aggFetch performs the GET and returns status and body without judging either,
// so a test can assert on a non-200 deliberately.
func aggFetch(t *testing.T, addr, path string) (int, []byte) {
	t.Helper()
	resp, err := httpGet(addr, path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: read body: %v", path, err)
	}
	return resp.StatusCode, body
}

// aggGet requires a 200 and decodes into v.
func aggGet(t *testing.T, addr, path string, v interface{}) {
	t.Helper()
	code, body := aggFetch(t, addr, path)
	if code != http.StatusOK {
		t.Fatalf("GET %s: expected 200, got %d — body: %s", path, code, trimForLog(body))
	}
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("GET %s: response does not match the LLD §10.1 shape: %v — body: %s",
			path, err, trimForLog(body))
	}
}

func trimForLog(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 800 {
		return s[:800] + "…"
	}
	if s == "" {
		return "(empty)"
	}
	return s
}

// aggregateURL builds an aggregate request for a target with the given query.
func aggregateURL(key, query string) string {
	p := "/api/targets/" + url.PathEscape(key) + "/aggregate"
	if query != "" {
		p += "?" + query
	}
	return p
}

// aggregate is the standard read: GET the aggregate and require the envelope.
func (w *aggWorld) aggregate(tgt aggTarget, query string) aggResponse {
	w.t.Helper()
	var out aggResponse
	path := aggregateURL(tgt.Key, query)
	aggGet(w.t, w.addr, path, &out)
	if out.Tiles == nil {
		w.t.Fatalf("GET %s: the response carries no `tiles` object; the aggregate headline "+
			"(unique / active / unconfirmed / fixed / critical) is part of the contract", path)
	}
	if out.Rows == nil {
		w.t.Fatalf("GET %s: `rows` is null; an empty result must be [] so the frontend can "+
			"render a table with no rows rather than crash on a nil list", path)
	}
	return out
}

// labelsOf renders a row set by seed label, so a count mismatch says WHICH rows
// came back rather than printing a list of uuids.
func (w *aggWorld) labelsOf(rows []aggReportRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if lbl, ok := w.labels[r.LineageID]; ok {
			out = append(out, lbl+"("+r.Status+"/"+r.Tier+"/"+r.Severity+")")
			continue
		}
		out = append(out, "UNSEEDED:"+r.LineageID)
	}
	sort.Strings(out)
	return out
}

// idSet is the set of lineage ids in a row list.
func idSet(rows []aggReportRow) map[string]bool {
	out := map[string]bool{}
	for _, r := range rows {
		out[r.LineageID] = true
	}
	return out
}

// labelSet is the set of seed labels the rows correspond to.
func (w *aggWorld) labelSet(rows []aggReportRow) map[string]bool {
	out := map[string]bool{}
	for _, r := range rows {
		out[w.labels[r.LineageID]] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// requireLabels asserts the row set is exactly the named seeds.
func (w *aggWorld) requireLabels(query string, rows []aggReportRow, want ...string) {
	w.t.Helper()
	got := w.labelSet(rows)
	wanted := map[string]bool{}
	for _, l := range want {
		wanted[l] = true
	}
	if len(got) != len(wanted) {
		w.t.Fatalf("?%s returned %d rows, want %d\n  got:  %v\n  want: %v",
			query, len(rows), len(want), sortedKeys(got), sortedKeys(wanted))
	}
	for l := range wanted {
		if !got[l] {
			w.t.Fatalf("?%s must include seed %q\n  got: %v", query, l, sortedKeys(got))
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Every issue ever reported is reachable.
// ─────────────────────────────────────────────────────────────────────────────

// TestAggregateIncludesEveryPastFinding is the user's stated requirement, and
// the reason this endpoint exists at all: EVERY issue ever reported for a
// codebase must be reachable from one page.
//
// Eight rows, one per status in the widened P0 vocabulary. The split is not
// arbitrary — model.ActiveLineageStatuses() is the single definition of
// "active", and it contains four statuses, two of which (`unconfirmed`,
// `regression`) an implementation written against the pre-0091 vocabulary drops
// on the floor:
//
//   - `unconfirmed` is the state 0091 INVENTED for "the scan could not decide".
//     A filter of `status = 'open'` hides exactly the rows that need a human,
//     which is the failure mode 0091 exists to prevent, one layer up.
//   - `regression` is a finding that came back. Hiding it from the active view
//     would make a repair-then-reappear cycle look like a permanent repair.
//
// And the four terminal states must not be lost either: `fixed` is the
// scanner's verdict and `resolved` / `false_positive` / `accepted_risk` are a
// human's. A report that cannot show them is a report where a dismissed finding
// cannot be reviewed and a closed one cannot be audited.
//
// The tiles are asserted IDENTICAL across both views, which is what makes the
// default view honest: standing on `active`, the `fixed` tile is the only thing
// that tells you the other rows exist.
func TestAggregateIncludesEveryPastFinding(t *testing.T) {
	w := newAggWorld(t)
	tgt := w.target("blu-simulator")
	base := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	w.scan(tgt, "audit-every-1", "", "main", base, "cwe")

	// One row per status. Severity `critical` is confined to an ACTIVE row so
	// the `critical` tile has the same value under either reading of what the
	// tiles are scoped to — the one tile this test deliberately does not turn
	// into a contract.
	seeds := []aggSeed{
		{Label: "open", Status: model.LineageStatusOpen, Severity: model.SeverityCritical, Provenance: "skill", SeenCount: 3},
		{Label: "inprogress", Status: model.LineageStatusInProgress, Severity: model.SeverityHigh, Provenance: "skill", SeenCount: 2},
		{Label: "unconfirmed", Status: model.LineageStatusUnconfirmed, Severity: model.SeverityMedium, Provenance: "llm_l5_verified", SeenCount: 1},
		{Label: "regression", Status: model.LineageStatusRegression, Severity: model.SeverityHigh, Provenance: "llm", SeenCount: 4},
		{Label: "fixed", Status: model.LineageStatusFixed, Severity: model.SeverityHigh, Provenance: "skill", SeenCount: 2},
		{Label: "resolved", Status: model.LineageStatusResolved, Severity: model.SeverityMedium, Provenance: "skill", SeenCount: 1},
		{Label: "falsepositive", Status: model.LineageStatusFalsePositive, Severity: model.SeverityLow, Provenance: "llm", SeenCount: 1},
		{Label: "acceptedrisk", Status: model.LineageStatusAcceptedRisk, Severity: model.SeverityLow, Provenance: "skill", SeenCount: 1},
	}
	for i := range seeds {
		s := seeds[i]
		s.Target = tgt
		s.Audit = "audit-every-1"
		s.Category = "CWE-506"
		s.RelPath = ".vscode/tasks.json"
		s.Line = 7 + i
		s.At = base
		w.row(s)
	}
	// One event per asserted row, so "the most recent event" is unambiguous
	// even at SQLite's one-second timestamp resolution.
	w.event(w.ids["open"], model.LineageEventConfirmedByEvidence, "audit-every-1", "quote found at line 7", base)
	w.event(w.ids["fixed"], model.LineageEventEvidenceGone, "audit-every-1", "quote absent from tasks.json", base)

	w.serve()

	activeLabels := []string{"open", "inprogress", "unconfirmed", "regression"}
	terminalLabels := []string{"fixed", "resolved", "falsepositive", "acceptedrisk"}

	// ── The default view. `status` omitted means `active`. ──────────────────
	def := w.aggregate(tgt, "")
	w.requireLabels("(no status)", def.Rows, activeLabels...)
	if def.Total != 4 {
		t.Fatalf("the default view is `active`: total = %d, want 4 (rows: %v)", def.Total, w.labelsOf(def.Rows))
	}
	for _, lbl := range []string{"unconfirmed", "regression"} {
		if !w.labelSet(def.Rows)[lbl] {
			t.Fatalf("%q is in model.ActiveLineageStatuses() and MUST appear in the default view — "+
				"a `status = 'open'` filter hides exactly the rows that need a human. Got: %v",
				lbl, w.labelsOf(def.Rows))
		}
	}
	for _, lbl := range terminalLabels {
		if w.labelSet(def.Rows)[lbl] {
			t.Fatalf("%q is terminal and must NOT appear in the default (active) view; got: %v",
				lbl, w.labelsOf(def.Rows))
		}
	}

	// ── `status=active` is the same view, spelled out. ──────────────────────
	explicit := w.aggregate(tgt, "status=active")
	if !sameIDs(idSet(def.Rows), idSet(explicit.Rows)) {
		t.Fatalf("`status=active` must be identical to the default view\n  default:  %v\n  explicit: %v",
			w.labelsOf(def.Rows), w.labelsOf(explicit.Rows))
	}

	// ── `status=all`: every issue ever reported. ────────────────────────────
	all := w.aggregate(tgt, "status=all")
	w.requireLabels("status=all", all.Rows, append(append([]string{}, activeLabels...), terminalLabels...)...)
	if all.Total != 8 {
		t.Fatalf("`status=all` must reach every issue ever reported for the target: total = %d, want 8 (rows: %v)",
			all.Total, w.labelsOf(all.Rows))
	}
	for _, lbl := range terminalLabels {
		if !w.labelSet(all.Rows)[lbl] {
			t.Fatalf("a %q finding is closed history, not deleted history: `status=all` must surface it. Got: %v",
				lbl, w.labelsOf(all.Rows))
		}
	}

	// ── The tiles describe the target, not the filter. ──────────────────────
	want := aggTiles{Unique: 8, Active: 4, Unconfirmed: 1, Fixed: 1, Critical: 1}
	for _, tc := range []struct {
		name  string
		tiles aggTiles
	}{{"default", *def.Tiles}, {"status=all", *all.Tiles}} {
		if tc.tiles != want {
			t.Fatalf("tiles under %s = %+v, want %+v. The tiles summarise the TARGET, not the "+
				"filtered rows: under the default `active` view the `fixed` tile is the only "+
				"signpost that closed findings exist", tc.name, tc.tiles, want)
		}
	}

	// ── Row projection: the fields the table renders. ───────────────────────
	openRow := findRowByID(t, all.Rows, w.ids["open"])
	if openRow.Status != string(model.LineageStatusOpen) {
		t.Fatalf("row.status = %q, want %q", openRow.Status, model.LineageStatusOpen)
	}
	if openRow.Severity != string(model.SeverityCritical) {
		t.Fatalf("row.severity = %q, want %q", openRow.Severity, model.SeverityCritical)
	}
	if openRow.Category != "CWE-506" {
		t.Fatalf("row.category = %q, want %q", openRow.Category, "CWE-506")
	}
	if openRow.RelPath != ".vscode/tasks.json" {
		t.Fatalf("row.rel_path = %q, want %q", openRow.RelPath, ".vscode/tasks.json")
	}
	if openRow.LineStart != 7 {
		t.Fatalf("row.line_start = %d, want 7", openRow.LineStart)
	}
	if openRow.SeenCount != 3 {
		t.Fatalf("row.seen_count = %d, want 3", openRow.SeenCount)
	}
	if openRow.Tier != model.TierDeterministic {
		t.Fatalf("row.tier for provenance %q = %q, want %q", "skill", openRow.Tier, model.TierDeterministic)
	}
	if openRow.Ref == "" || !strings.HasPrefix(openRow.Ref, "VLT-") {
		t.Fatalf("row.ref = %q, want the stable VLT-XXXX reference a human cites", openRow.Ref)
	}
	if openRow.LastEvent != string(model.LineageEventConfirmedByEvidence) {
		t.Fatalf("row.last_event = %q, want %q — the aggregate's whole point is showing WHY a row "+
			"is where it is", openRow.LastEvent, model.LineageEventConfirmedByEvidence)
	}
	if got := mustParseTime(t, "first_seen_at", openRow.FirstSeenAt); !got.Equal(base) {
		t.Fatalf("row.first_seen_at = %s, want the row's first_found_at %s", got, base)
	}
	if got := mustParseTime(t, "last_seen_at", openRow.LastSeenAt); got.Before(base) {
		t.Fatalf("row.last_seen_at %s precedes first_seen_at %s", got, base)
	}

	fixedRow := findRowByID(t, all.Rows, w.ids["fixed"])
	if fixedRow.LastEvent != string(model.LineageEventEvidenceGone) {
		t.Fatalf("the fixed row's last_event = %q, want %q", fixedRow.LastEvent, model.LineageEventEvidenceGone)
	}
	llmRow := findRowByID(t, all.Rows, w.ids["regression"])
	if llmRow.Tier != model.TierLLM {
		t.Fatalf("row.tier for provenance %q = %q, want %q", "llm", llmRow.Tier, model.TierLLM)
	}
}

func sameIDs(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func findRowByID(t *testing.T, rows []aggReportRow, id string) aggReportRow {
	t.Helper()
	for _, r := range rows {
		if r.LineageID == id {
			return r
		}
	}
	t.Fatalf("lineage row %q is missing from the aggregate response", id)
	return aggReportRow{}
}

func mustParseTime(t *testing.T, field, v string) time.Time {
	t.Helper()
	if v == "" {
		t.Fatalf("%s is empty; the aggregate table renders it as a column", field)
	}
	parsed, err := time.Parse(time.RFC3339, v)
	if err != nil {
		t.Fatalf("%s = %q is not RFC3339: %v", field, v, err)
	}
	return parsed.UTC()
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Filters and paging.
// ─────────────────────────────────────────────────────────────────────────────

// TestAggregateFiltersAndPaging pins every query parameter in the §10.1
// signature, and the one property that is easy to get wrong in all of them:
// `total` is the size of the FILTERED set BEFORE paging.
//
// A `total` that counts the returned page turns the pager into a lie (page 2 of
// 1) and a `total` that counts the whole target makes every filter look like it
// did nothing. Both are single-line mistakes and neither is visible on a page
// that happens to fit.
//
// The fixture is twelve open rows across three scans of one target, chosen so
// each filter's answer is a different subset and no two filters can be
// satisfied by the same off-by-one. One row carries an EMPTY provenance, which
// model.TierOf defines as deterministic — 5,750 persisted findings predate the
// field, and a `tier=det` filter that misses them hides a fifth of the corpus.
func TestAggregateFiltersAndPaging(t *testing.T) {
	w := newAggWorld(t)
	tgt := w.target("vulture")
	base := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)
	w.scan(tgt, "scan-b1", "", "main", base, "cwe")
	w.scan(tgt, "scan-b2", "", "main", base.Add(time.Hour), "cwe")
	w.scan(tgt, "scan-b3", "", "main", base.Add(2*time.Hour), "cwe")

	// label   audit     provenance          tier  severity  seen
	table := []struct {
		label string
		audit string
		prov  string
		sev   model.Severity
		seen  int
	}{
		{"f01", "scan-b1", "skill", model.SeverityCritical, 5},
		{"f02", "scan-b1", "", model.SeverityHigh, 4}, // empty provenance ⇒ det
		{"f03", "scan-b1", "catalog_rollup", model.SeverityMedium, 3},
		{"f04", "scan-b1", "llm", model.SeverityCritical, 3},
		{"f05", "scan-b1", "llm_l5_verified", model.SeverityLow, 2},
		{"f06", "scan-b2", "skill", model.SeverityHigh, 2},
		{"f07", "scan-b2", "skill", model.SeverityLow, 1},
		{"f08", "scan-b2", "llm", model.SeverityHigh, 1},
		{"f09", "scan-b2", "signature_trusted", model.SeverityMedium, 1},
		{"f10", "scan-b3", "skill", model.SeverityCritical, 1},
		{"f11", "scan-b3", "llm_tier3", model.SeverityMedium, 4},
		{"f12", "scan-b3", "skill", model.SeverityHigh, 2},
	}
	for i, e := range table {
		w.row(aggSeed{
			Label: e.label, Target: tgt, Audit: e.audit,
			Status: model.LineageStatusOpen, Severity: e.sev, Category: "CWE-78",
			RelPath: fmt.Sprintf("src/mod_%s.py", e.label), Line: i + 1,
			Provenance: e.prov, SeenCount: e.seen, At: base,
		})
	}
	w.serve()

	all := []string{"f01", "f02", "f03", "f04", "f05", "f06", "f07", "f08", "f09", "f10", "f11", "f12"}

	// ── Unfiltered, unpaged: the whole target, and the default page size. ───
	full := w.aggregate(tgt, "")
	w.requireLabels("(none)", full.Rows, all...)
	if full.Total != 12 {
		t.Fatalf("unfiltered total = %d, want 12", full.Total)
	}
	if full.Page != 1 || full.PageSize != 50 {
		t.Fatalf("with no paging parameters the response must echo page=1 page_size=50 (§10.1), got page=%d page_size=%d",
			full.Page, full.PageSize)
	}

	// ── tier ────────────────────────────────────────────────────────────────
	det := w.aggregate(tgt, "tier=det")
	w.requireLabels("tier=det", det.Rows, "f01", "f02", "f03", "f06", "f07", "f09", "f10", "f12")
	if det.Total != 8 {
		t.Fatalf("tier=det total = %d, want 8", det.Total)
	}
	for _, r := range det.Rows {
		if r.Tier != model.TierDeterministic {
			t.Fatalf("tier=det returned %q with tier %q", w.labels[r.LineageID], r.Tier)
		}
	}
	if !w.labelSet(det.Rows)["f02"] {
		t.Fatalf("tier=det must include f02, whose provenance is EMPTY: model.TierOf defines the " +
			"empty string as deterministic, and 5,750 persisted findings carry nothing else")
	}
	llm := w.aggregate(tgt, "tier=llm")
	w.requireLabels("tier=llm", llm.Rows, "f04", "f05", "f08", "f11")
	if llm.Total != 4 {
		t.Fatalf("tier=llm total = %d, want 4", llm.Total)
	}
	for _, r := range llm.Rows {
		if r.Tier != model.TierLLM {
			t.Fatalf("tier=llm returned %q with tier %q", w.labels[r.LineageID], r.Tier)
		}
	}

	// ── min_seen ────────────────────────────────────────────────────────────
	w.requireLabels("min_seen=3", w.aggregate(tgt, "min_seen=3").Rows, "f01", "f02", "f03", "f04", "f11")
	w.requireLabels("min_seen=4", w.aggregate(tgt, "min_seen=4").Rows, "f01", "f02", "f11")
	w.requireLabels("min_seen=1", w.aggregate(tgt, "min_seen=1").Rows, all...)

	// ── severity ────────────────────────────────────────────────────────────
	w.requireLabels("severity=critical", w.aggregate(tgt, "severity=critical").Rows, "f01", "f04", "f10")
	w.requireLabels("severity=critical,high", w.aggregate(tgt, "severity=critical,high").Rows,
		"f01", "f02", "f04", "f06", "f08", "f10", "f12")

	// ── scans subset ────────────────────────────────────────────────────────
	w.requireLabels("scans=scan-b1", w.aggregate(tgt, "scans=scan-b1").Rows, "f01", "f02", "f03", "f04", "f05")
	w.requireLabels("scans=scan-b1,scan-b3", w.aggregate(tgt, "scans=scan-b1,scan-b3").Rows,
		"f01", "f02", "f03", "f04", "f05", "f10", "f11", "f12")

	// ── filters compose ─────────────────────────────────────────────────────
	w.requireLabels("tier=llm&severity=critical", w.aggregate(tgt, "tier=llm&severity=critical").Rows, "f04")
	w.requireLabels("scans=scan-b1&tier=det&min_seen=3",
		w.aggregate(tgt, "scans=scan-b1&tier=det&min_seen=3").Rows, "f01", "f02", "f03")

	// ── paging: `total` is the count BEFORE paging. ─────────────────────────
	seen := map[string]bool{}
	for _, tc := range []struct {
		page, wantRows int
	}{{1, 5}, {2, 5}, {3, 2}} {
		q := fmt.Sprintf("page=%d&page_size=5", tc.page)
		got := w.aggregate(tgt, q)
		if len(got.Rows) != tc.wantRows {
			t.Fatalf("?%s returned %d rows, want %d: %v", q, len(got.Rows), tc.wantRows, w.labelsOf(got.Rows))
		}
		if got.Total != 12 {
			t.Fatalf("?%s: total = %d, want 12 — `total` counts the filtered set BEFORE paging, "+
				"otherwise the pager can never know how many pages there are", q, got.Total)
		}
		if got.Page != tc.page || got.PageSize != 5 {
			t.Fatalf("?%s echoed page=%d page_size=%d", q, got.Page, got.PageSize)
		}
		for _, r := range got.Rows {
			if seen[r.LineageID] {
				t.Fatalf("?%s repeated %q from an earlier page: paging needs a total order, or "+
					"rows are both duplicated and lost across pages", q, w.labels[r.LineageID])
			}
			seen[r.LineageID] = true
		}
	}
	if len(seen) != 12 {
		t.Fatalf("pages 1-3 at page_size=5 covered %d of 12 rows; every row must appear on exactly one page", len(seen))
	}

	// A page past the end is empty, not an error, and does not change `total`.
	beyond := w.aggregate(tgt, "page=4&page_size=5")
	if len(beyond.Rows) != 0 {
		t.Fatalf("page 4 of 3 must be empty, got %v", w.labelsOf(beyond.Rows))
	}
	if beyond.Total != 12 {
		t.Fatalf("page 4 of 3: total = %d, want 12", beyond.Total)
	}

	// `total` survives a filter combined with paging.
	filteredPage := w.aggregate(tgt, "tier=det&page=1&page_size=3")
	if filteredPage.Total != 8 {
		t.Fatalf("tier=det&page_size=3: total = %d, want 8 (the filtered set, not the page)", filteredPage.Total)
	}
	if len(filteredPage.Rows) != 3 {
		t.Fatalf("tier=det&page_size=3 returned %d rows, want 3", len(filteredPage.Rows))
	}
	lastFiltered := w.aggregate(tgt, "tier=det&page=3&page_size=3")
	if len(lastFiltered.Rows) != 2 {
		t.Fatalf("tier=det page 3 of 3 at page_size=3 must hold the remaining 2 rows, got %d", len(lastFiltered.Rows))
	}

	// A page below 1 is clamped, not rejected: the frontend's deep links are
	// user-editable and a 500 on `?page=0` is worse than the first page.
	zero := w.aggregate(tgt, "page=0&page_size=5")
	if zero.Page != 1 {
		t.Fatalf("?page=0 must clamp to page 1, got page=%d", zero.Page)
	}
	first := w.aggregate(tgt, "page=1&page_size=5")
	if !sameIDs(idSet(zero.Rows), idSet(first.Rows)) {
		t.Fatalf("?page=0 must return the same rows as ?page=1\n  page=0: %v\n  page=1: %v",
			w.labelsOf(zero.Rows), w.labelsOf(first.Rows))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. A row is a finding, not an occurrence.
// ─────────────────────────────────────────────────────────────────────────────

// TestAggregateRowsAreUniqueFindingsNotPerScanCopies is the property the whole
// report is named for.
//
// It is driven through the REAL ingest path — three RecordScanOutcome passes,
// the same code that runs when an agent finishes — rather than by planting a
// row with seen_count=3, because the number under test is produced by that path
// and a hand-set value would test nothing but the SELECT.
//
// Two columns are asserted and they mean different things:
//
//   - `seen_count` — how many scans found THIS finding.
//   - `scan_count` — how many scans are in the selected set.
//
// Together they are the "seen in 2 of 5 scans" bar. Collapsing them into one
// number is the natural mistake, and it is precisely the mistake that makes a
// finding reported once by five scans indistinguishable from five findings.
func TestAggregateRowsAreUniqueFindingsNotPerScanCopies(t *testing.T) {
	w := newAggWorld(t)
	tgt := w.target("recurring")
	base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)

	// The finding every scan re-reports.
	persistent := model.Finding{
		AgentType: "cwe", Severity: model.SeverityCritical, Category: "CWE-506",
		Title: "Task runs a shell command on folder open", FilePath: ".vscode/tasks.json",
		LineStart: 7, LineEnd: 7,
		Fingerprint: "fp-v1-persistent", FingerprintV2: "fp-v2-persistent", Provenance: "skill",
	}
	// A second finding, first reported by the LAST scan only. It shares the
	// target's scan_count but has a seen_count of 1, which is what separates
	// the two columns.
	latecomer := model.Finding{
		AgentType: "cwe", Severity: model.SeverityHigh, Category: "CWE-78",
		Title: "Command injection in build script", FilePath: "scripts/build.sh",
		LineStart: 12, LineEnd: 12,
		Fingerprint: "fp-v1-latecomer", FingerprintV2: "fp-v2-latecomer", Provenance: "skill",
	}

	for i, auditID := range []string{"scan-c1", "scan-c2", "scan-c3"} {
		audit := w.scan(tgt, auditID, "", "main", base.Add(time.Duration(i)*time.Hour), "cwe")
		findings := []model.Finding{persistent}
		if auditID == "scan-c3" {
			findings = append(findings, latecomer)
		}
		// evidenceResult declares the 0091 result schema, so the closure pass
		// is allowed to act and the sighting is recorded rather than skipped as
		// scope-unknown.
		if err := w.svc.RecordScanOutcome(audit, w.sources[auditID], "cwe", evidenceResult(findings...)); err != nil {
			t.Fatalf("%s: %v", auditID, err)
		}
	}
	w.serve()

	got := w.aggregate(tgt, "status=all")
	if len(got.Rows) != 2 || got.Total != 2 {
		t.Fatalf("three scans of two distinct findings must yield TWO rows, not one per "+
			"(finding, scan): total = %d, rows = %d\n%s",
			got.Total, len(got.Rows), renderRows(got.Rows))
	}
	if got.Tiles.Unique != 2 {
		t.Fatalf("tiles.unique = %d, want 2 — the headline counts unique findings, not occurrences", got.Tiles.Unique)
	}

	byPath := map[string]aggReportRow{}
	for _, r := range got.Rows {
		byPath[r.RelPath] = r
	}
	rec, ok := byPath[".vscode/tasks.json"]
	if !ok {
		t.Fatalf("the finding every scan reported is missing from the aggregate:\n%s", renderRows(got.Rows))
	}
	if rec.SeenCount != 3 {
		t.Fatalf("the finding was reported by all three scans: seen_count = %d, want 3", rec.SeenCount)
	}
	if rec.ScanCount != 3 {
		t.Fatalf("scan_count is the DENOMINATOR — how many scans are in the selected set, not how "+
			"many saw this finding: got %d, want 3", rec.ScanCount)
	}
	late, ok := byPath["scripts/build.sh"]
	if !ok {
		t.Fatalf("the finding raised by the last scan only is missing:\n%s", renderRows(got.Rows))
	}
	if late.SeenCount != 1 {
		t.Fatalf("a finding first seen on the last scan has seen_count = %d, want 1", late.SeenCount)
	}
	if late.ScanCount != 3 {
		t.Fatalf("scan_count is a property of the SELECTION, so it is 3 for every row of this "+
			"target: got %d for the latecomer", late.ScanCount)
	}

	// Narrowing the selection narrows the denominator, not the finding.
	one := w.aggregate(tgt, "status=all&scans=scan-c3")
	for _, r := range one.Rows {
		if r.ScanCount != 1 {
			t.Fatalf("with `scans=scan-c3` selected, scan_count must be 1, got %d for %q", r.ScanCount, r.RelPath)
		}
	}
}

func renderRows(rows []aggReportRow) string {
	out := ""
	for _, r := range rows {
		out += fmt.Sprintf("    %-14s %-9s %-4s seen=%d/%d %s\n",
			r.Ref, r.Status, r.Tier, r.SeenCount, r.ScanCount, r.RelPath)
	}
	if out == "" {
		return "    (no rows)\n"
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. The merge stays merged.
// ─────────────────────────────────────────────────────────────────────────────

// TestAggregateExcludesMergedRows guards the clause `repository.notMerged`
// documents and every lineage REPORT read carries.
//
// Migration 027 retired duplicate rows — the same finding recorded twice
// because the tree was scanned under two path forms — by pointing the loser's
// `merged_into` at the survivor rather than deleting it, so that a VLT link
// printed in an old ticket still leads somewhere. That choice puts the burden on
// every read: a report that forgets the clause shows the duplicate the migration
// existed to remove, double-counts it in `unique`, and offers the user two rows
// that can drift into different statuses.
//
// The asymmetry is asserted too: the aggregate must hide the loser, and
// `/api/lineage/{loser}` must still resolve. Hiding it there would defeat the
// reason it was kept.
func TestAggregateExcludesMergedRows(t *testing.T) {
	w := newAggWorld(t)
	tgt := w.target("merged-target")
	base := time.Now().UTC().Add(-12 * time.Hour).Truncate(time.Second)
	w.scan(tgt, "scan-d1", "", "main", base, "cwe")

	survivor := w.row(aggSeed{
		Label: "survivor", Target: tgt, Audit: "scan-d1", Status: model.LineageStatusOpen,
		Severity: model.SeverityCritical, Category: "CWE-506", RelPath: ".vscode/tasks.json",
		Line: 7, Provenance: "skill", SeenCount: 2, At: base,
	})
	loser := w.row(aggSeed{
		Label: "loser", Target: tgt, Audit: "scan-d1", Status: model.LineageStatusOpen,
		Severity: model.SeverityCritical, Category: "CWE-506", RelPath: ".vscode/tasks.json",
		Line: 7, Provenance: "skill", SeenCount: 1, At: base,
	})
	// The merge itself. Written as SQL because it is migration 027's own work —
	// there is no runtime path that retires a row, and inventing a repository
	// method for the fixture would test the fixture.
	if _, err := w.base.DB().Exec(
		`UPDATE finding_lineage SET merged_into = ? WHERE id = ?`, survivor.ID, loser.ID); err != nil {
		t.Fatalf("merge %s into %s: %v", loser.ID, survivor.ID, err)
	}
	w.serve()

	got := w.aggregate(tgt, "status=all")
	if len(got.Rows) != 1 || got.Total != 1 {
		t.Fatalf("a row with `merged_into` set is a retired duplicate and must never appear in the "+
			"report: total = %d, rows = %d\n%s", got.Total, len(got.Rows), renderRows(got.Rows))
	}
	if got.Rows[0].LineageID != survivor.ID {
		t.Fatalf("the aggregate returned the RETIRED row %q instead of its survivor %q",
			got.Rows[0].LineageID, survivor.ID)
	}
	if got.Tiles.Unique != 1 || got.Tiles.Active != 1 {
		t.Fatalf("the tiles must not count a retired duplicate: %+v, want unique=1 active=1", *got.Tiles)
	}

	// The loser is hidden from the report, NOT deleted: a stale VLT link still
	// has to lead somewhere.
	code, body := aggFetch(t, w.addr, "/api/lineage/"+loser.ID)
	if code != http.StatusOK {
		t.Fatalf("GET /api/lineage/%s (a merged loser) = %d, want 200 — the row is MARKED, not "+
			"deleted, precisely so an old VLT link resolves. Body: %s", loser.ID, code, trimForLog(body))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. The target list and its scan history.
// ─────────────────────────────────────────────────────────────────────────────

// TestTargetsListAndScans pins the two navigation endpoints: the dashboard's
// list of codebases and one codebase's scan history.
//
// Both exist because a target is now a first-class thing. `/api/targets` is what
// the dashboard renders instead of a flat audit list, and its counts have to
// come from the lineage rows rather than from the last scan's findings — the
// number a user needs is "34 open issues in this codebase", not "34 findings in
// the most recent run".
//
// `/api/targets/{key}/scans` is the history rail. Three properties matter and
// each has a way of being silently wrong:
//
//   - NEWEST FIRST. A rail that renders oldest-first puts the scan you just ran
//     at the bottom of a scrolling list.
//   - `sub_path`. A `.vscode` scan and a root scan are the same target (§7.2)
//     and would otherwise be indistinguishable in the rail — which is exactly
//     how the reference incident's two scans looked identical.
//   - det/llm SPLIT. The two tiers obey different closure rules, so "what did
//     this scan actually contribute" is a two-number answer.
func TestTargetsListAndScans(t *testing.T) {
	w := newAggWorld(t)
	blu := w.target("blu-simulator")
	vul := w.target("vulture")
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)

	a1 := base
	a2 := base.Add(time.Hour)
	a3 := base.Add(2 * time.Hour)
	w.scan(blu, "audit-a1", "", "main", a1, "cwe")
	w.scan(blu, "audit-a2", ".vscode", "main", a2, "cwe")
	w.scan(blu, "audit-a3", "", "feature/x", a3, "cwe", "owasp")
	w.scan(vul, "audit-v1", "", "main", base.Add(30*time.Minute), "cwe")

	// blu-simulator: six rows spread across its three scans.
	//   audit-a1 → 2 det (one open, one fixed) + 1 llm (open)
	//   audit-a2 → 1 det (unconfirmed)
	//   audit-a3 → 2 llm (one open, one false_positive)
	// active = open + open + unconfirmed + open = 4; unconfirmed = 1; fixed = 1.
	for _, s := range []aggSeed{
		{Label: "b-a1-det-open", Audit: "audit-a1", Status: model.LineageStatusOpen, Provenance: "skill"},
		{Label: "b-a1-det-fixed", Audit: "audit-a1", Status: model.LineageStatusFixed, Provenance: "skill"},
		{Label: "b-a1-llm-open", Audit: "audit-a1", Status: model.LineageStatusOpen, Provenance: "llm"},
		{Label: "b-a2-det-unconf", Audit: "audit-a2", Status: model.LineageStatusUnconfirmed, Provenance: "catalog_rollup"},
		{Label: "b-a3-llm-open", Audit: "audit-a3", Status: model.LineageStatusOpen, Provenance: "llm_l5_verified"},
		{Label: "b-a3-llm-fp", Audit: "audit-a3", Status: model.LineageStatusFalsePositive, Provenance: "llm_tier3"},
	} {
		s.Target = blu
		s.Severity = model.SeverityHigh
		s.Category = "CWE-78"
		s.RelPath = "src/" + s.Label + ".py"
		s.Line = 3
		s.SeenCount = 1
		s.At = a1
		w.row(s)
	}
	w.row(aggSeed{
		Label: "v-open", Target: vul, Audit: "audit-v1", Status: model.LineageStatusOpen,
		Severity: model.SeverityLow, Category: "CWE-200", RelPath: "internal/x.go",
		Line: 1, Provenance: "skill", SeenCount: 1, At: base,
	})
	w.serve()

	// ── GET /api/targets ────────────────────────────────────────────────────
	var targets []aggTargetRow
	aggGet(t, w.addr, "/api/targets", &targets)
	if len(targets) != 2 {
		t.Fatalf("GET /api/targets returned %d targets, want 2 (%s, %s): %+v",
			len(targets), blu.Name, vul.Name, targets)
	}
	byKey := map[string]aggTargetRow{}
	for _, tr := range targets {
		byKey[tr.TargetKey] = tr
	}
	bluRow, ok := byKey[blu.Key]
	if !ok {
		t.Fatalf("GET /api/targets does not list %q (key %q); got keys %v",
			blu.Name, blu.Key, sortedTargetKeys(targets))
	}
	if bluRow.DisplayName != "blu-simulator" {
		t.Fatalf("display_name = %q, want %q — the dashboard cannot render a sha1 to a human",
			bluRow.DisplayName, "blu-simulator")
	}
	if bluRow.ScanCount != 3 {
		t.Fatalf("%s scan_count = %d, want 3", blu.Name, bluRow.ScanCount)
	}
	if bluRow.ActiveCount != 4 {
		t.Fatalf("%s active_count = %d, want 4 — active is model.ActiveLineageStatuses(), so the "+
			"`unconfirmed` row counts and the `false_positive` one does not", blu.Name, bluRow.ActiveCount)
	}
	if bluRow.UnconfirmedCount != 1 {
		t.Fatalf("%s unconfirmed_count = %d, want 1", blu.Name, bluRow.UnconfirmedCount)
	}
	if bluRow.FixedCount != 1 {
		t.Fatalf("%s fixed_count = %d, want 1", blu.Name, bluRow.FixedCount)
	}
	if bluRow.LastAuditID != "audit-a3" {
		t.Fatalf("%s last_audit_id = %q, want %q (the newest scan)", blu.Name, bluRow.LastAuditID, "audit-a3")
	}
	if got := mustParseTime(t, "last_scan_at", bluRow.LastScanAt); !got.Equal(a3) {
		t.Fatalf("%s last_scan_at = %s, want %s", blu.Name, got, a3)
	}

	vulRow, ok := byKey[vul.Key]
	if !ok {
		t.Fatalf("GET /api/targets does not list %q; got keys %v", vul.Name, sortedTargetKeys(targets))
	}
	if vulRow.DisplayName != "vulture" || vulRow.ScanCount != 1 ||
		vulRow.ActiveCount != 1 || vulRow.UnconfirmedCount != 0 || vulRow.FixedCount != 0 {
		t.Fatalf("second target row = %+v, want display_name=vulture scan_count=1 active=1 unconfirmed=0 fixed=0", vulRow)
	}

	// ── GET /api/targets/{key}/scans ────────────────────────────────────────
	var scans []aggScanRow
	aggGet(t, w.addr, "/api/targets/"+url.PathEscape(blu.Key)+"/scans", &scans)
	if len(scans) != 3 {
		t.Fatalf("GET .../scans returned %d scans, want 3: %+v", len(scans), scans)
	}
	wantOrder := []string{"audit-a3", "audit-a2", "audit-a1"}
	for i, want := range wantOrder {
		if scans[i].AuditID != want {
			t.Fatalf("the scan history is NEWEST FIRST: position %d = %q, want %q (full order %v)",
				i, scans[i].AuditID, want, scanIDs(scans))
		}
	}
	byAudit := map[string]aggScanRow{}
	for _, s := range scans {
		byAudit[s.AuditID] = s
	}
	if byAudit["audit-a2"].SubPath != ".vscode" {
		t.Fatalf("a scan of <root>/.vscode must report sub_path %q, got %q — a sub-path scan "+
			"inherits its root's target key (§7.2), so the offset is the ONLY thing distinguishing "+
			"it from a root scan in the rail", ".vscode", byAudit["audit-a2"].SubPath)
	}
	if byAudit["audit-a1"].SubPath != "" || byAudit["audit-a3"].SubPath != "" {
		t.Fatalf("a scan standing on the target root has an empty sub_path, got a1=%q a3=%q",
			byAudit["audit-a1"].SubPath, byAudit["audit-a3"].SubPath)
	}
	if byAudit["audit-a3"].GitBranch != "feature/x" || byAudit["audit-a1"].GitBranch != "main" {
		t.Fatalf("git_branch: a1=%q a3=%q, want main / feature/x — closure is per branch (§7.4), so "+
			"the rail has to say which branch a scan stood on",
			byAudit["audit-a1"].GitBranch, byAudit["audit-a3"].GitBranch)
	}
	if got := mustParseTime(t, "created_at", byAudit["audit-a1"].CreatedAt); !got.Equal(a1) {
		t.Fatalf("audit-a1 created_at = %s, want %s", got, a1)
	}
	for _, tc := range []struct {
		audit    string
		det, llm int
	}{
		{"audit-a1", 2, 1},
		{"audit-a2", 1, 0},
		{"audit-a3", 0, 2},
	} {
		got := byAudit[tc.audit]
		if got.DetCount != tc.det || got.LLMCount != tc.llm {
			t.Fatalf("%s det/llm = %d/%d, want %d/%d — the two tiers obey different closure rules, "+
				"so the rail reports them apart", tc.audit, got.DetCount, got.LLMCount, tc.det, tc.llm)
		}
	}
	if !sameStrings(byAudit["audit-a3"].Types, []string{"cwe", "owasp"}) {
		t.Fatalf("audit-a3 types = %v, want [cwe owasp]", byAudit["audit-a3"].Types)
	}
	if !sameStrings(byAudit["audit-a1"].Types, []string{"cwe"}) {
		t.Fatalf("audit-a1 types = %v, want [cwe]", byAudit["audit-a1"].Types)
	}

	// The second target's history is its own.
	var vulScans []aggScanRow
	aggGet(t, w.addr, "/api/targets/"+url.PathEscape(vul.Key)+"/scans", &vulScans)
	if len(vulScans) != 1 || vulScans[0].AuditID != "audit-v1" {
		t.Fatalf("%s scan history = %+v, want exactly audit-v1", vul.Name, vulScans)
	}

	// An unknown key must never fall through to another target's history.
	code, body := aggFetch(t, w.addr, "/api/targets/"+url.PathEscape("marker:0000000000000000000000000000000000000000")+"/scans")
	if code == http.StatusOK {
		var stray []aggScanRow
		if err := json.Unmarshal(body, &stray); err == nil && len(stray) != 0 {
			t.Fatalf("an unknown target key returned %d scans; it must be 404 or an empty list, "+
				"never another target's history: %+v", len(stray), stray)
		}
	}
}

func sortedTargetKeys(rows []aggTargetRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.TargetKey)
	}
	sort.Strings(out)
	return out
}

func scanIDs(rows []aggScanRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.AuditID)
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string{}, a...)
	y := append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. The detail endpoint gains evidence and seen_in.
// ─────────────────────────────────────────────────────────────────────────────

// TestLineageDetailCarriesEvidenceAndSeenIn pins the two blocks §10.1 adds to
// the EXISTING detail endpoint, and the fact that they are additions.
//
// `evidence` is what makes 0091 legible to a human. Without it the detail page
// can say a row is `open` but not that a scan RE-READ the file and found the
// quote still there — the difference between "nobody mentioned it" and "it is
// still in the code", which is the entire subject of this feature.
//
// `seen_in` is deliberately here and NOWHERE ELSE. It is the list of audits
// that reported this finding, and the only way to compute it is to read
// `findings` by `fingerprint_v2`. That is the join the aggregate is forbidden to
// make (TestAggregateNoJoinToFindings): one row's worth of it on a detail page
// is cheap and indexed, a whole report's worth is the thing that makes the
// report unusable. The fixture therefore plants a MIDDLE audit that reported a
// DIFFERENT finding, so an implementation that shortcuts to "every audit of the
// target" is caught rather than accidentally right.
func TestLineageDetailCarriesEvidenceAndSeenIn(t *testing.T) {
	w := newAggWorld(t)
	tgt := w.target("evidence-target")
	base := time.Now().UTC().Add(-5 * time.Hour).Truncate(time.Second)
	w.scan(tgt, "audit-e1", "", "main", base, "cwe")
	w.scan(tgt, "audit-e2", "", "main", base.Add(time.Hour), "cwe")
	w.scan(tgt, "audit-e3", "", "main", base.Add(2*time.Hour), "cwe")

	tracked := w.row(aggSeed{
		Label: "tracked", Target: tgt, Audit: "audit-e1", Status: model.LineageStatusOpen,
		Severity: model.SeverityCritical, Category: "CWE-506", RelPath: ".vscode/tasks.json",
		Line: 7, Provenance: "llm_l5_verified", SeenCount: 2, At: base,
	})

	// The findings rows `seen_in` is computed from. audit-e1 and audit-e3
	// reported the tracked finding; audit-e2 reported something else.
	saveFinding := func(auditID, v1, v2, path string) {
		t.Helper()
		if err := w.base.SaveFindings(auditID, []model.Finding{{
			AuditID: auditID, AgentType: "cwe", Severity: model.SeverityCritical,
			Category: "CWE-506", Title: "Task runs a shell command on folder open",
			FilePath: path, LineStart: 7, LineEnd: 7,
			Fingerprint: v1, FingerprintV2: v2, Provenance: "llm_l5_verified",
		}}); err != nil {
			t.Fatalf("save findings for %s: %v", auditID, err)
		}
	}
	saveFinding("audit-e1", tracked.Fingerprint, tracked.FingerprintV2, ".vscode/tasks.json")
	saveFinding("audit-e2", "fp-v1-unrelated", "fp-v2-unrelated", "src/other.py")
	saveFinding("audit-e3", tracked.Fingerprint, tracked.FingerprintV2, ".vscode/tasks.json")

	// The evidence outcome itself, written through the production path so the
	// columns hold what a real confirmation would leave behind.
	const fileHash = "sha256:9f2c1b7d4e6a8c0f1234567890abcdef1234567890abcdef1234567890abcdef"
	if err := w.lineage.ApplyEvidence(tracked.ID, repository.LineageEvidenceUpdate{
		AuditID: "audit-e3", FileHash: fileHash, IncrementSeen: true,
		LineStart: 7, LineEnd: 9, UpdateWindow: true,
	}); err != nil {
		t.Fatalf("apply evidence: %v", err)
	}
	const reason = "quote matched at line 7"
	w.event(tracked.ID, model.LineageEventDetected, "audit-e1", "", base)
	w.event(tracked.ID, model.LineageEventConfirmedByEvidence, "audit-e3", reason, base.Add(2*time.Hour))
	w.serve()

	var detail aggLineageDetail
	aggGet(t, w.addr, "/api/lineage/"+tracked.ID, &detail)

	// The pre-0091 shape survives: this endpoint is EXTENDED, not replaced.
	if detail.Lineage == nil || detail.Lineage.ID != tracked.ID {
		t.Fatalf("the existing `lineage` object must still be present and unchanged; got %+v", detail.Lineage)
	}
	if len(detail.Events) == 0 {
		t.Fatalf("the existing `events` list must still be present; the timeline renders from it")
	}

	// ── evidence ────────────────────────────────────────────────────────────
	if detail.Evidence == nil {
		t.Fatalf("GET /api/lineage/{id} must carry an `evidence` block (§10.1): without it the " +
			"detail page cannot distinguish \"the scan re-read the file and the quote is still " +
			"there\" from \"nobody mentioned it this time\"")
	}
	ev := detail.Evidence
	if ev.LastOutcome != "confirmed" {
		t.Fatalf("evidence.last_outcome = %q, want %q — the last evidence event on this row is %q",
			ev.LastOutcome, "confirmed", model.LineageEventConfirmedByEvidence)
	}
	if ev.Reason != reason {
		t.Fatalf("evidence.reason = %q, want %q (the reason recorded on the confirming event)", ev.Reason, reason)
	}
	if ev.LineStart != 7 || ev.LineEnd != 9 {
		t.Fatalf("evidence window = %d-%d, want 7-9 (the window the verifier confirmed)", ev.LineStart, ev.LineEnd)
	}
	if ev.FileHash != fileHash {
		t.Fatalf("evidence.file_hash = %q, want %q — it is what bounds the fixed-row re-check (§6.3)",
			ev.FileHash, fileHash)
	}
	if got := mustParseTime(t, "evidence.checked_at", ev.CheckedAt); got.Before(base) {
		t.Fatalf("evidence.checked_at = %s precedes the first scan %s", got, base)
	}

	// ── seen_in ─────────────────────────────────────────────────────────────
	if detail.SeenIn == nil {
		t.Fatalf("GET /api/lineage/{id} must carry `seen_in` (§10.1): the audits that reported this " +
			"finding, computed HERE by fingerprint_v2 and nowhere else")
	}
	gotSeen := map[string]bool{}
	for _, id := range detail.SeenIn {
		gotSeen[id] = true
	}
	for _, want := range []string{"audit-e1", "audit-e3"} {
		if !gotSeen[want] {
			t.Fatalf("seen_in must contain %q, which reported this fingerprint_v2: got %v", want, detail.SeenIn)
		}
	}
	if gotSeen["audit-e2"] {
		t.Fatalf("seen_in contains %q, which scanned the target but reported a DIFFERENT finding. "+
			"`seen_in` is the audits that saw THIS finding (matched by fingerprint_v2), not every "+
			"audit of the target: got %v", "audit-e2", detail.SeenIn)
	}
	if len(detail.SeenIn) != 2 {
		t.Fatalf("seen_in = %v, want exactly [audit-e1 audit-e3]", detail.SeenIn)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. The aggregate never reads `findings`.
// ─────────────────────────────────────────────────────────────────────────────

// aggregateMethodRE matches the repository methods that answer the aggregate.
// A structural test needs a name to look for; this is it, and the failure
// message says so.
var aggregateMethodRE = regexp.MustCompile(`Aggregate`)

// findingsTableRE matches a reference to the `findings` table as a whole word.
// `finding_lineage`, `findings_count` and `lineage_events` are all left alone —
// the character classes on either side are what keeps the check from firing on
// a column name that merely starts with the same letters.
var findingsTableRE = regexp.MustCompile(`(?i)(^|[^a-z0-9_])findings([^a-z0-9_]|$)`)

// TestAggregateNoJoinToFindings is the one test here that reads code instead of
// responses, and it is deliberate.
//
// "The aggregate must not join `findings`" is a claim about the QUERY, and no
// black-box observation can settle it. A response-shape test passes with the
// join present. A timing test passes too: on a seeded database of twelve rows
// the join costs microseconds. It only becomes visible against the live table's
// 93,341 rows — at which point it is a production incident, not a test failure.
//
// So the SQL is read. The check is scoped to string literals inside the
// aggregate methods, because that is where SQL lives; comments and identifiers
// are untouched, so a method may explain in prose exactly why it does not touch
// `findings` without failing its own test.
//
// It also pins the rule that every repository change lands in BOTH dialects: a
// Postgres-only aggregate leaves every SQLite install — the default for a local
// dev stack and for the native installer — with a 500.
func TestAggregateNoJoinToFindings(t *testing.T) {
	dir := repositoryPackageDir(t)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}

	type found struct {
		receiver string
		method   string
		file     string
		literals []string
	}
	var methods []found
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || fn.Body == nil {
					continue
				}
				if !aggregateMethodRE.MatchString(fn.Name.Name) {
					continue
				}
				methods = append(methods, found{
					receiver: receiverTypeName(fn),
					method:   fn.Name.Name,
					file:     filepath.Base(path),
					literals: stringLiteralsIn(fn.Body),
				})
			}
		}
	}

	if len(methods) == 0 {
		t.Fatalf("no aggregate repository method found in %s.\n"+
			"GET /api/targets/{key}/aggregate is backed by a repository method whose name contains "+
			"\"Aggregate\" (e.g. AggregateByTarget), implemented on BOTH *PostgresLineageRepo and "+
			"*SQLiteLineageRepo. This test reads that method's SQL to prove it never touches the "+
			"`findings` table.", dir)
	}

	byReceiver := map[string]bool{}
	for _, m := range methods {
		byReceiver[m.receiver] = true
		for _, lit := range m.literals {
			if !findingsTableRE.MatchString(lit) {
				continue
			}
			t.Fatalf("%s.%s (%s) reads the `findings` table:\n\n%s\n\n"+
				"The aggregate is computed from `finding_lineage` ALONE (§10.1). `findings` holds "+
				"93,341 rows against finding_lineage's 10,663, and that join is what makes this "+
				"endpoint slow. `seen_in` is the ONLY thing allowed to read `findings`, and only on "+
				"GET /api/lineage/{id}, one row at a time.",
				m.receiver, m.method, m.file, indent(lit))
		}
	}

	for _, want := range []string{"PostgresLineageRepo", "SQLiteLineageRepo"} {
		if !byReceiver[want] {
			t.Fatalf("no aggregate method on *%s (found: %v).\n"+
				"Repository changes land in BOTH dialects: Postgres is production, SQLite is the "+
				"local dev fallback and the native installer's only store.", want, sortedKeys(byReceiver))
		}
	}

	// Guard against a vacuous pass: if the methods carried no SQL at all, the
	// check above would be satisfied by a stub.
	touchesLineage := false
	for _, m := range methods {
		for _, lit := range m.literals {
			if strings.Contains(strings.ToLower(lit), "finding_lineage") {
				touchesLineage = true
			}
		}
	}
	if !touchesLineage {
		t.Fatalf("the aggregate methods contain no SQL mentioning `finding_lineage`, so this test " +
			"proved nothing. The aggregate reads finding_lineage through idx_lineage_active_target.")
	}
}

// repositoryPackageDir locates internal/repository relative to this test file,
// so the test does not depend on the working directory `go test` was run from.
func repositoryPackageDir(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this test file")
	}
	dir := filepath.Join(filepath.Dir(self), "..", "..", "internal", "repository")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	return dir
}

// receiverTypeName renders a method's receiver type, pointer stripped.
func receiverTypeName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	expr := fn.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// stringLiteralsIn collects every string literal in a function body — where SQL
// lives, and nowhere a comment can reach.
func stringLiteralsIn(body *ast.BlockStmt) []string {
	var out []string
	ast.Inspect(body, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		out = append(out, strings.Trim(lit.Value, "`\""))
		return true
	})
	return out
}

func indent(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := range lines {
		lines[i] = "    " + strings.TrimSpace(lines[i])
	}
	return strings.Join(lines, "\n")
}

// compile-time guard: these tests read the aggregate through the repository
// interface's own type, so a rename of the lineage repository breaks them
// loudly rather than silently skipping the contract.
var _ = func(repo repository.LineageRepository) {
	_ = repo.ActiveByTarget
}
