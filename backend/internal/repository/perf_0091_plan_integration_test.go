//go:build integration

// Feature 0091 §10.1 — the PLAN behind the aggregate, not just its latency.
//
// WHY A PLAN TEST AND NOT ONLY A TIMER. A latency gate answers "is it fast on
// this corpus"; it cannot answer "is it fast BECAUSE of an index". Those come
// apart in exactly the way that matters at scale: a sequential scan over
// 10,000 rows is a few milliseconds and passes any wall-clock gate, and the
// same plan over 200,000 rows is seconds. The plan is the invariant; the
// milliseconds are a consequence of it on today's data.
//
// The queries here are built from the SAME fragments the repository executes
// (reportFilterSQL, aggregateRowCols, aggregateOrderSQL, tilesSelectSQL), so
// this cannot drift from what production runs — a copy of the SQL would only
// pin the plan of the copy.
//
// Gated by the `integration` tag and POSTGRES_TEST_DSN.
package repository

import (
	"fmt"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/vulture/backend/internal/model"
)

// explain runs EXPLAIN (ANALYZE, BUFFERS) and returns the plan text.
func explain(t *testing.T, f *pgTargetFixture, query string, args []interface{}) string {
	t.Helper()
	rows, err := f.owner.DB().Query("EXPLAIN (ANALYZE, BUFFERS) "+query, args...)
	if err != nil {
		t.Fatalf("explain: %v\nquery: %s", err, query)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		lines = append(lines, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	return strings.Join(lines, "\n")
}

// TestPGAggregatePlanAtScale reports the plan of every statement the aggregate
// endpoint issues, and fails if the row-page statement — the one a user waits
// on — falls back to a sequential scan of finding_lineage.
func TestPGAggregatePlanAtScale(t *testing.T) {
	f := newPGTargetFixture(t)

	statuses := []model.LineageStatus{
		model.LineageStatusOpen, model.LineageStatusOpen, model.LineageStatusOpen,
		model.LineageStatusUnconfirmed, model.LineageStatusInProgress,
		model.LineageStatusRegression, model.LineageStatusFixed,
		model.LineageStatusResolved, model.LineageStatusFalsePositive,
		model.LineageStatusAcceptedRisk,
	}
	severities := []string{"critical", "high", "medium", "low", "info"}
	provenances := []string{"skill", "llm", "llm_l5_verified", "catalog_rollup", "", "signature_trusted"}

	sizes := []struct {
		name string
		rows int
	}{
		{"blu-simulator", 4200}, {"openclaw", 2600}, {"vulture", 1600},
		{"idattestor", 1150}, {"magicrouter", 700},
	}
	ref := 1
	var biggest string
	for i, spec := range sizes {
		key := f.target(spec.name, 5)
		if i == 0 {
			biggest = key
		}
		seeds := make([]pgLineageSeed, 0, spec.rows)
		for j := range spec.rows {
			seeds = append(seeds, pgLineageSeed{
				status:     statuses[j%len(statuses)],
				severity:   severities[j%len(severities)],
				provenance: provenances[j%len(provenances)],
				seenCount:  1 + j%9,
				auditIdx:   j % 5,
			})
		}
		ids := f.bulkSeed(key, seeds, ref)
		ref += spec.rows
		f.seedEvents(ids)
	}
	if _, err := f.owner.DB().Exec(`ANALYZE finding_lineage`); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if _, err := f.owner.DB().Exec(`ANALYZE lineage_events`); err != nil {
		t.Fatalf("analyze events: %v", err)
	}
	var total int
	if err := f.owner.DB().QueryRow(`SELECT COUNT(*) FROM finding_lineage`).Scan(&total); err != nil {
		t.Fatalf("count: %v", err)
	}
	t.Logf("corpus: %d finding_lineage rows over %d targets", total, len(sizes))

	cases := []struct {
		name  string
		query model.AggregateQuery
	}{
		{"default (active, page 1)", model.AggregateQuery{TargetKey: biggest, Page: 1, PageSize: 50}},
		{"status=all page 1", model.AggregateQuery{TargetKey: biggest, IncludeTerminal: true, Page: 1, PageSize: 50}},
		{"status=all page 20", model.AggregateQuery{TargetKey: biggest, IncludeTerminal: true, Page: 20, PageSize: 50}},
		{"status=all page 84 (last)", model.AggregateQuery{TargetKey: biggest, IncludeTerminal: true, Page: 84, PageSize: 50}},
		{"tier=llm", model.AggregateQuery{TargetKey: biggest, Tier: model.TierLLM, Page: 1, PageSize: 50}},
		{"min_seen=2", model.AggregateQuery{TargetKey: biggest, MinSeen: 2, Page: 1, PageSize: 50}},
		{"severity=critical,high", model.AggregateQuery{TargetKey: biggest, Severities: []string{"critical", "high"}, Page: 1, PageSize: 50}},
	}

	for _, tc := range cases {
		d := &sqlDialect{pg: true}
		where := reportFilterSQL(d, keysOf(biggest), tc.query)
		limit := d.ph(tc.query.PageSize)
		offset := d.ph(tc.query.Offset())
		q := `SELECT ` + aggregateRowCols + ` FROM finding_lineage WHERE ` + where +
			aggregateOrderSQL + ` LIMIT ` + limit + ` OFFSET ` + offset
		plan := explain(t, f, q, d.args)
		t.Logf("\n──── PAGE QUERY: %s ────\n%s", tc.name, plan)
		if strings.Contains(plan, "Seq Scan on finding_lineage") {
			t.Errorf("%s: the page query sequential-scans finding_lineage:\n%s", tc.name, plan)
		}
	}

	// The tiles pass is an aggregate over the whole target selection and is
	// EXPECTED to read every row of the target; what it must not do is read
	// every row of the TABLE.
	dt := &sqlDialect{pg: true}
	tiles := `SELECT ` + tilesSelectSQL(dt) + ` FROM finding_lineage WHERE ` +
		targetScopeSQL(dt, keysOf(biggest), model.AggregateQuery{TargetKey: biggest})
	t.Logf("\n──── TILES QUERY ────\n%s", explain(t, f, tiles, dt.args))

	dc := &sqlDialect{pg: true}
	count := `SELECT COUNT(*) FROM finding_lineage WHERE ` +
		reportFilterSQL(dc, keysOf(biggest), model.AggregateQuery{TargetKey: biggest, Page: 1, PageSize: 50})
	t.Logf("\n──── TOTAL (COUNT) QUERY ────\n%s", explain(t, f, count, dc.args))

	// The last-event lookup, bounded by one page of ids.
	var ids []string
	rows, err := f.owner.DB().Query(
		`SELECT id::text FROM finding_lineage WHERE target_key = $1 LIMIT 50`, biggest)
	if err != nil {
		t.Fatalf("page ids: %v", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan id: %v", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	de := &sqlDialect{pg: true}
	ev := lastEventQuery(de, ids)
	plan := explain(t, f, ev, de.args)
	t.Logf("\n──── LAST-EVENT QUERY (50 ids) ────\n%s", plan)
	if strings.Contains(plan, "Seq Scan on lineage_events") {
		t.Errorf("the last-event lookup sequential-scans lineage_events:\n%s", plan)
	}

	// The scan rail loads alongside the report, so its plan is part of the
	// same page load. tierCountQuery is the expensive half: a three-way UNION
	// over the target's rows.
	dtc := &sqlDialect{pg: true}
	t.Logf("\n──── SCAN RAIL: tier counts (3-way UNION) ────\n%s",
		explain(t, f, tierCountQuery(dtc, keysOf(biggest)), dtc.args))

	// GET /api/targets is the dashboard, and its lineage half is the ONE read
	// in the feature with no target predicate: it groups the WHOLE table. That
	// is correct (it has to count every target) and it is also the read whose
	// cost tracks the installation's total row count rather than one
	// codebase's, so its plan is worth having on the record.
	dtl := &sqlDialect{pg: true}
	active := activeStatusList(dtl)
	unconfirmed := dtl.ph(string(model.LineageStatusUnconfirmed))
	fixed := dtl.ph(string(model.LineageStatusFixed))
	t.Logf("\n──── /api/targets: lineage counts (whole table) ────\n%s", explain(t, f, `
		SELECT COALESCE(target_key,''),
		       COALESCE(SUM(CASE WHEN current_status IN `+active+` THEN 1 ELSE 0 END),0),
		       COALESCE(SUM(CASE WHEN current_status = `+unconfirmed+` THEN 1 ELSE 0 END),0),
		       COALESCE(SUM(CASE WHEN current_status = `+fixed+` THEN 1 ELSE 0 END),0)
		  FROM finding_lineage
		 WHERE COALESCE(target_key,'') <> ''`+notMerged+`
		 GROUP BY COALESCE(target_key,'')`, dtl.args))

	// Which indexes exist on the table, for the record.
	idxRows, err := f.owner.DB().Query(
		`SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'finding_lineage'
		 ORDER BY indexname`)
	if err != nil {
		t.Fatalf("pg_indexes: %v", err)
	}
	defer idxRows.Close()
	for idxRows.Next() {
		var name, def string
		if err := idxRows.Scan(&name, &def); err != nil {
			t.Fatalf("scan index: %v", err)
		}
		t.Log(fmt.Sprintf("index %-28s %s", name, def))
	}
}

// keysOf is the key list a target-scoped read scopes to. The synthetic corpus
// here has no 027-backfilled twins to bridge to, so it is the target's own key
// alone — the same shape TargetReadKeys returns for a converged installation,
// and the one whose plan matters.
func keysOf(targetKey string) []string { return []string{targetKey} }
