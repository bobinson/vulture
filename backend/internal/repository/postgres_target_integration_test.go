//go:build integration

// Postgres integration + performance tests for the feature 0091 P4 target
// endpoints.
//
// WHY THIS FILE EXISTS. The P4 contract suite (test/e2e/targets_api_test.go)
// runs against SQLite, and the two dialects are not the same code: the window
// functions, the `::text` casts on the UUID columns, the `$n` numbering the
// shared placeholder builder emits and the TEXT[] `types` column are all
// Postgres-only, and every one of them compiles, vets and passes the entire
// committed suite while being wrong.
//
// The second test is the §10.1 performance gate. It is here rather than in the
// E2E suite because latency is only meaningful against a realistic corpus: on
// the twelve-row fixture the contract tests use, a query that joins `findings`
// and one that does not are indistinguishable.
//
// Gated by the `integration` tag and POSTGRES_TEST_DSN, like every other
// Postgres file in this package. Each test gets its own schema.
package repository

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/vulture/backend/internal/model"
)

// pgTargetFixture is a set of codebases on one migrated schema: for each, a
// source carrying the target key, some audits, and lineage rows attributed to
// them.
type pgTargetFixture struct {
	repo   *PostgresLineageRepo
	owner  *PostgresRepo
	t      *testing.T
	audits map[string][]string // target key -> audit ids, oldest first
}

func newPGTargetFixture(t *testing.T) *pgTargetFixture {
	t.Helper()
	repo, owner, _ := newPGLineageRepo(t)
	return &pgTargetFixture{repo: repo, owner: owner, t: t, audits: map[string][]string{}}
}

// target creates one codebase with `scans` audits, each on its own source row
// so a sub-path scan can be modelled, and returns its target key.
func (f *pgTargetFixture) target(name string, scans int) string {
	f.t.Helper()
	key := "marker:" + name
	base := time.Now().UTC().Add(-time.Duration(scans) * time.Hour).Truncate(time.Second)
	for i := range scans {
		path := "/repos/" + name
		if i == 1 {
			path += "/.vscode" // one sub-path scan per target, as in the incident
		}
		srcID := uuid.NewString()
		if err := f.owner.CreateSource(&model.Source{
			ID: srcID, Type: model.SourceTypeLocal, Path: path, TargetKey: key,
			GitBranch: "main", CreatedAt: base.Add(time.Duration(i) * time.Hour),
		}); err != nil {
			f.t.Fatalf("create source for %s: %v", name, err)
		}
		auditID := uuid.NewString()
		if err := f.owner.CreateAudit(&model.Audit{
			ID: auditID, SourceID: srcID, Types: []string{"cwe", "owasp"},
			Status: model.AuditStatusCompleted, CreatedAt: base.Add(time.Duration(i) * time.Hour),
		}); err != nil {
			f.t.Fatalf("create audit for %s: %v", name, err)
		}
		f.audits[key] = append(f.audits[key], auditID)
	}
	return key
}

// pgLineageSeed is one row to bulk-insert.
type pgLineageSeed struct {
	status     model.LineageStatus
	severity   string
	provenance string
	seenCount  int
	auditIdx   int
}

// bulkSeed inserts lineage rows with a multi-row INSERT.
//
// UpsertLineage is not used: it is a SELECT plus a transaction per row, which
// at ten thousand rows measures the writer rather than the reader this file is
// about.
func (f *pgTargetFixture) bulkSeed(key string, seeds []pgLineageSeed, refBase int) []string {
	f.t.Helper()
	audits := f.audits[key]
	ids := make([]string, 0, len(seeds))
	const cols = 17
	for start := 0; start < len(seeds); start += 500 {
		end := min(start+500, len(seeds))
		values := make([]string, 0, end-start)
		args := make([]interface{}, 0, (end-start)*cols)
		for i := start; i < end; i++ {
			s := seeds[i]
			id := uuid.NewString()
			ids = append(ids, id)
			auditID := audits[s.auditIdx%len(audits)]
			now := time.Now().UTC()
			ph := make([]string, cols)
			for c := range ph {
				ph[c] = fmt.Sprintf("$%d", len(args)+c+1)
			}
			values = append(values, "("+strings.Join(ph, ",")+")")
			args = append(args,
				id, fmt.Sprintf("fp-v1-%s-%d", key, i), "/repos/"+key, "cwe",
				string(s.status), auditID, now, s.severity, "CWE-506",
				fmt.Sprintf("seeded finding %d", i), fmt.Sprintf("src/mod_%d.py", i),
				key, fmt.Sprintf("fp-v2-%s-%d", key, i), s.provenance, s.seenCount,
				auditID, refBase+i)
		}
		stmt := `INSERT INTO finding_lineage (
			id, fingerprint, source_path, agent_type, current_status, first_audit_id,
			first_found_at, severity, category, title, file_path,
			target_key, fingerprint_v2, provenance, seen_count, last_seen_audit_id, ref_number
		) VALUES ` + strings.Join(values, ",")
		if _, err := f.owner.DB().Exec(stmt, args...); err != nil {
			f.t.Fatalf("bulk seed lineage: %v", err)
		}
	}
	return ids
}

// TestPGTargetReadsRunOnPostgres is the dialect-parity check: every P4 query,
// executed, on the store that serves production.
func TestPGTargetReadsRunOnPostgres(t *testing.T) {
	f := newPGTargetFixture(t)
	blu := f.target("blu", 3)
	vul := f.target("vul", 1)

	// blu: one row per status, so the tiles and the status filter are both
	// exercised; severities and provenances split so tier and severity are too.
	statuses := []model.LineageStatus{
		model.LineageStatusOpen, model.LineageStatusInProgress,
		model.LineageStatusUnconfirmed, model.LineageStatusRegression,
		model.LineageStatusFixed, model.LineageStatusResolved,
		model.LineageStatusFalsePositive, model.LineageStatusAcceptedRisk,
	}
	seeds := make([]pgLineageSeed, 0, len(statuses))
	for i, st := range statuses {
		prov := "skill"
		if i%2 == 1 {
			prov = "llm_l5_verified"
		}
		sev := "high"
		if st == model.LineageStatusOpen {
			sev = "critical"
		}
		seeds = append(seeds, pgLineageSeed{status: st, severity: sev, provenance: prov, seenCount: i + 1, auditIdx: i})
	}
	ids := f.bulkSeed(blu, seeds, 1000)
	f.bulkSeed(vul, []pgLineageSeed{{status: model.LineageStatusOpen, severity: "low", provenance: "", seenCount: 1}}, 2000)

	// ── /api/targets ────────────────────────────────────────────────────────
	targets, err := f.repo.ListTargets()
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	byKey := map[string]model.TargetSummary{}
	for _, tr := range targets {
		byKey[tr.TargetKey] = tr
	}
	got := byKey[blu]
	if got.ScanCount != 3 {
		t.Errorf("blu scan_count = %d, want 3", got.ScanCount)
	}
	if got.ActiveCount != 4 || got.UnconfirmedCount != 1 || got.FixedCount != 1 {
		t.Errorf("blu counts = active %d / unconfirmed %d / fixed %d, want 4 / 1 / 1",
			got.ActiveCount, got.UnconfirmedCount, got.FixedCount)
	}
	if got.LastAuditID != f.audits[blu][2] {
		t.Errorf("blu last_audit_id = %q, want the newest scan %q", got.LastAuditID, f.audits[blu][2])
	}
	if got.RootPath != "/repos/blu" {
		t.Errorf("blu root_path = %q, want the shallowest recorded path", got.RootPath)
	}
	if byKey[vul].ScanCount != 1 || byKey[vul].ActiveCount != 1 {
		t.Errorf("vul row = %+v, want scan_count 1 active 1", byKey[vul])
	}

	// ── /api/targets/{key}/scans ────────────────────────────────────────────
	scans, err := f.repo.TargetScans(blu)
	if err != nil {
		t.Fatalf("TargetScans: %v", err)
	}
	if len(scans) != 3 {
		t.Fatalf("TargetScans returned %d, want 3", len(scans))
	}
	if scans[0].AuditID != f.audits[blu][2] {
		t.Errorf("scan history is newest-first: got %q first, want %q", scans[0].AuditID, f.audits[blu][2])
	}
	if len(scans[0].Types) != 2 {
		t.Errorf("types = %v, want the TEXT[] column decoded into two entries", scans[0].Types)
	}
	total := 0
	for _, s := range scans {
		total += s.DetCount + s.LLMCount
	}
	if total != len(statuses) {
		t.Errorf("det+llm across the history = %d, want %d (every row attributed once)", total, len(statuses))
	}

	// ── /api/targets/{key}/aggregate ────────────────────────────────────────
	base := model.AggregateQuery{TargetKey: blu, Page: 1, PageSize: 50}
	active, err := f.repo.AggregateByTarget(base)
	if err != nil {
		t.Fatalf("AggregateByTarget: %v", err)
	}
	if active.Total != 4 || len(active.Rows) != 4 {
		t.Errorf("default view: total %d rows %d, want 4 / 4", active.Total, len(active.Rows))
	}
	wantTiles := model.AggregateTiles{Unique: 8, Active: 4, Unconfirmed: 1, Fixed: 1, Critical: 1}
	if active.Tiles != wantTiles {
		t.Errorf("tiles = %+v, want %+v", active.Tiles, wantTiles)
	}
	all := base
	all.IncludeTerminal = true
	report, err := f.repo.AggregateByTarget(all)
	if err != nil {
		t.Fatalf("AggregateByTarget(status=all): %v", err)
	}
	if report.Total != 8 {
		t.Errorf("status=all total = %d, want 8", report.Total)
	}
	if report.Tiles != wantTiles {
		t.Errorf("tiles must not move with the status filter: %+v, want %+v", report.Tiles, wantTiles)
	}

	for _, tc := range []struct {
		name  string
		query model.AggregateQuery
		want  int
	}{
		{"tier=det", model.AggregateQuery{TargetKey: blu, IncludeTerminal: true, Tier: model.TierDeterministic, Page: 1, PageSize: 50}, 4},
		{"tier=llm", model.AggregateQuery{TargetKey: blu, IncludeTerminal: true, Tier: model.TierLLM, Page: 1, PageSize: 50}, 4},
		{"min_seen=5", model.AggregateQuery{TargetKey: blu, IncludeTerminal: true, MinSeen: 5, Page: 1, PageSize: 50}, 4},
		{"severity", model.AggregateQuery{TargetKey: blu, IncludeTerminal: true, Severities: []string{"critical"}, Page: 1, PageSize: 50}, 1},
		{"scans", model.AggregateQuery{TargetKey: blu, IncludeTerminal: true, Scans: []string{f.audits[blu][0]}, Page: 1, PageSize: 50}, 3},
		{"page 2", model.AggregateQuery{TargetKey: blu, IncludeTerminal: true, Page: 2, PageSize: 5}, 8},
	} {
		got, err := f.repo.AggregateByTarget(tc.query)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got.Total != tc.want {
			t.Errorf("%s: total = %d, want %d", tc.name, got.Total, tc.want)
		}
	}

	// ── the denominator, and the one read that touches `findings` ───────────
	n, err := f.repo.CountTargetScans(blu, nil)
	if err != nil || n != 3 {
		t.Errorf("CountTargetScans(all) = %d, %v; want 3", n, err)
	}
	n, err = f.repo.CountTargetScans(blu, []string{f.audits[blu][0]})
	if err != nil || n != 1 {
		t.Errorf("CountTargetScans(one) = %d, %v; want 1", n, err)
	}
	row, err := f.repo.GetLineage(ids[0])
	if err != nil || row == nil {
		t.Fatalf("GetLineage: %v", err)
	}
	seenIn, err := f.repo.SeenInAudits(row)
	if err != nil {
		t.Fatalf("SeenInAudits: %v", err)
	}
	if len(seenIn) != 1 || seenIn[0] != f.audits[blu][0] {
		t.Errorf("seen_in = %v, want the one audit the row is attributed to", seenIn)
	}
}

// TestPGAggregatePerformanceAtScale is the §10.1 gate: p95 under 200ms for a
// 50-row page on a realistic corpus.
//
// Ten thousand lineage rows across four targets, which is the order of the
// live store (10,663 rows) and eight times the largest single target in it
// (1,156). The measurement covers the WHOLE endpoint read — tiles, the
// filtered count, the page and the last-event lookup — because that is what a
// user waits for.
func TestPGAggregatePerformanceAtScale(t *testing.T) {
	f := newPGTargetFixture(t)
	statuses := []model.LineageStatus{
		model.LineageStatusOpen, model.LineageStatusInProgress, model.LineageStatusRegression,
		model.LineageStatusUnconfirmed, model.LineageStatusFixed, model.LineageStatusResolved,
		model.LineageStatusFalsePositive, model.LineageStatusAcceptedRisk,
	}
	severities := []string{"critical", "high", "medium", "low", "info"}
	provenances := []string{"skill", "llm", "llm_l5_verified", "catalog_rollup", "", "signature_trusted"}

	const perTarget = 2600
	var biggest string
	ref := 1
	for ti, name := range []string{"alpha", "beta", "gamma", "delta"} {
		key := f.target(name, 5)
		if ti == 0 {
			biggest = key
		}
		seeds := make([]pgLineageSeed, 0, perTarget)
		for i := range perTarget {
			seeds = append(seeds, pgLineageSeed{
				status:     statuses[i%len(statuses)],
				severity:   severities[i%len(severities)],
				provenance: provenances[i%len(provenances)],
				seenCount:  1 + i%7,
				auditIdx:   i % 5,
			})
		}
		ids := f.bulkSeed(key, seeds, ref)
		ref += perTarget
		f.seedEvents(ids)
	}

	var count int
	if err := f.owner.DB().QueryRow(`SELECT COUNT(*) FROM finding_lineage`).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count < 10000 {
		t.Fatalf("corpus is %d rows, want at least 10000 — the gate is meaningless below that", count)
	}
	if _, err := f.owner.DB().Exec(`ANALYZE finding_lineage`); err != nil {
		t.Fatalf("analyze: %v", err)
	}

	queries := []struct {
		name  string
		query model.AggregateQuery
	}{
		{"default (active, page 1)", model.AggregateQuery{TargetKey: biggest, Page: 1, PageSize: 50}},
		{"status=all", model.AggregateQuery{TargetKey: biggest, IncludeTerminal: true, Page: 1, PageSize: 50}},
		{"deep page", model.AggregateQuery{TargetKey: biggest, IncludeTerminal: true, Page: 20, PageSize: 50}},
		{"tier+severity+min_seen", model.AggregateQuery{
			TargetKey: biggest, IncludeTerminal: true, Tier: model.TierLLM,
			Severities: []string{"critical", "high"}, MinSeen: 3, Page: 1, PageSize: 50}},
		{"scans subset", model.AggregateQuery{
			TargetKey: biggest, IncludeTerminal: true, Page: 1, PageSize: 50,
			Scans: f.audits[biggest][:2]}},
	}
	for _, tc := range queries {
		p50, p95 := f.measure(tc.query)
		t.Logf("aggregate %-24s corpus=%d rows  p50=%6.2fms  p95=%6.2fms", tc.name, count,
			float64(p50.Microseconds())/1000, float64(p95.Microseconds())/1000)
		if p95 > 200*time.Millisecond {
			t.Errorf("%s: p95 %.2fms exceeds the 200ms gate", tc.name, float64(p95.Microseconds())/1000)
		}
	}
}

// seedEvents gives a slice of the rows a timeline, so the last-event lookup
// has something to resolve and the event table is not empty.
func (f *pgTargetFixture) seedEvents(ids []string) {
	f.t.Helper()
	kinds := []model.LineageEventType{
		model.LineageEventDetected, model.LineageEventConfirmedByEvidence,
		model.LineageEventEvidenceGone, model.LineageEventUnconfirmable,
	}
	now := time.Now().UTC()
	for start := 0; start < len(ids); start += 500 {
		end := min(start+500, len(ids))
		values := make([]string, 0, (end-start)*2)
		args := make([]interface{}, 0, (end-start)*2*4)
		for i := start; i < end; i++ {
			for k := range 2 {
				ph := []string{
					fmt.Sprintf("$%d", len(args)+1), fmt.Sprintf("$%d", len(args)+2),
					fmt.Sprintf("$%d", len(args)+3), fmt.Sprintf("$%d", len(args)+4),
				}
				values = append(values, "("+strings.Join(ph, ",")+")")
				args = append(args, uuid.NewString(), ids[i],
					string(kinds[(i+k)%len(kinds)]), now.Add(time.Duration(k)*time.Minute))
			}
		}
		if _, err := f.owner.DB().Exec(
			`INSERT INTO lineage_events (id, lineage_id, event_type, created_at) VALUES `+
				strings.Join(values, ","), args...); err != nil {
			f.t.Fatalf("seed events: %v", err)
		}
	}
}

// measure runs the read 30 times after a warm-up and returns p50 and p95.
func (f *pgTargetFixture) measure(q model.AggregateQuery) (p50, p95 time.Duration) {
	f.t.Helper()
	const runs = 30
	if _, err := f.repo.AggregateByTarget(q); err != nil {
		f.t.Fatalf("warm-up: %v", err)
	}
	samples := make([]time.Duration, 0, runs)
	for range runs {
		start := time.Now()
		if _, err := f.repo.AggregateByTarget(q); err != nil {
			f.t.Fatalf("aggregate: %v", err)
		}
		samples = append(samples, time.Since(start))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2], samples[int(float64(len(samples))*0.95)]
}
