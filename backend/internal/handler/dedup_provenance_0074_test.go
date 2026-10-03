package handler

// Feature 0074 P4 (plan §5.5, §6 P4, §8 "dedup merge" rows) — the cross-agent
// merge records EVERY contributing tier, keeps the loser's reasoning, and
// accounts for every LLM row it collapses.
//
// What is pinned here, by acceptance criterion:
//
//   - AC17  A skill row and an LLM row for the same defect at the same site
//     merge into ONE row whose validation.provenance_origins names both
//     tiers — when the skill row wins (equal severity), when the LLM row wins
//     (strictly more severe), for a SAME-AGENT pair (which today records
//     nothing at all: CrossAgentOrigins excludes the winner's own agent), and
//     when the swallowing row is a rollup parent.
//   - AC11  provenance_origins is a TOP-LEVEL key of the validation map and
//     never an entry of checks[], so it can never be a voter input: recording
//     it must not move validation_status or validation_confidence.
//   - AC18  The losing rows' descriptions survive in
//     validation.merged_descriptions, capped at 2,048 bytes per entry and 8
//     entries per row, with truncation marked.
//   - AC22  crossAgentKeyWithRoot is byte-identical to a golden table for
//     fixed inputs with a NON-EMPTY root (regression pin: P4 must not touch
//     the key).
//   - AC19  One structured `dedup_buckets` log line per agent with emitted,
//     collapsed_agent, collapsed_go, unique, lost; lost == 0 whenever every
//     LLM row is unique; a non-zero loss is reported, never hidden.
//   - Version skew (§5.5 item 3): an agent that sends no counters (an older
//     agent) has its buckets reported `unavailable`, and lost is never
//     derived from zeros.
//
// Shape-agnostic on purpose where the plan does not fix a shape: values are
// normalised through JSON (which is also what persistence does), and a
// merged_descriptions entry may be a bare string or an object carrying a
// `description` key.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/vulture/backend/internal/agui"
	"github.com/vulture/backend/internal/model"
)

const (
	mergedDescEntryCapBytes = 2048
	mergedDescEntryCapCount = 8
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// asJSONValue normalises any validation value through JSON into dst, the way
// both repositories store it. Absent keys leave dst untouched.
func asJSONValue(t *testing.T, v interface{}, dst interface{}) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		t.Fatalf("validation value %s has the wrong shape: %v", b, err)
	}
}

// provenanceOriginsOf returns validation.provenance_origins as strings, or nil.
func provenanceOriginsOf(t *testing.T, f model.Finding) []string {
	t.Helper()
	raw, ok := f.Validation["provenance_origins"]
	if !ok {
		return nil
	}
	var out []string
	asJSONValue(t, raw, &out)
	return out
}

// mergedDescriptionsOf returns each merged_descriptions entry as
// (text, truncatedFlag). A bare-string entry has no flag.
func mergedDescriptionsOf(t *testing.T, f model.Finding) []mergedDesc {
	t.Helper()
	raw, ok := f.Validation["merged_descriptions"]
	if !ok {
		return nil
	}
	var entries []json.RawMessage
	asJSONValue(t, raw, &entries)
	out := make([]mergedDesc, 0, len(entries))
	for _, e := range entries {
		out = append(out, decodeMergedDesc(t, e))
	}
	return out
}

type mergedDesc struct {
	text      string
	truncated bool
}

func decodeMergedDesc(t *testing.T, e json.RawMessage) mergedDesc {
	t.Helper()
	var s string
	if json.Unmarshal(e, &s) == nil {
		return mergedDesc{text: s}
	}
	var obj struct {
		Description string `json:"description"`
		Truncated   bool   `json:"truncated"`
	}
	if err := json.Unmarshal(e, &obj); err != nil {
		t.Fatalf("merged_descriptions entry %s is neither a string nor an object: %v", e, err)
	}
	return mergedDesc{text: obj.Description, truncated: obj.Truncated}
}

// marksTruncation: an entry is marked by an explicit flag or an in-text marker.
func (m mergedDesc) marksTruncation() bool {
	return m.truncated || strings.Contains(strings.ToLower(m.text), "truncated")
}

func containsAll(have []string, want ...string) bool {
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

// mergeOne runs the merge and requires exactly one survivor.
func mergeOne(t *testing.T, rows ...model.Finding) model.Finding {
	t.Helper()
	out, _ := dedupCrossAgentWithShadow(rows, "")
	if len(out) != 1 {
		t.Fatalf("fixture did not collapse: %d rows survived, want 1", len(out))
	}
	return out[0]
}

// bothOrders yields the rows in input order and reversed: the record must not
// depend on which agent's frame arrived first.
func bothOrders(a, b model.Finding) [][]model.Finding {
	return [][]model.Finding{{a, b}, {b, a}}
}

func assertNamesBothTiers(t *testing.T, f model.Finding, want ...string) {
	t.Helper()
	got := provenanceOriginsOf(t, f)
	if !containsAll(got, want...) {
		t.Errorf("survivor %s (provenance %q): validation.provenance_origins = %v, want it to name %v",
			f.ID, f.Provenance, got, want)
	}
}

// ---------------------------------------------------------------------------
// AC17 — provenance_origins names every contributing tier
// ---------------------------------------------------------------------------

// AC17, T4.1 direction 1: the skill row wins at equal severity; the LLM row
// that collapsed into it must still be on the record.
func TestProvenanceOrigins_SkillWinsAtEqualSeverity_0074(t *testing.T) {
	skill := deterministicRow("skill-1", model.SeverityHigh)
	llm := llmRow("llm-1", model.SeverityHigh, 0)
	for _, rows := range bothOrders(skill, llm) {
		got := mergeOne(t, rows...)
		if got.ID != "skill-1" {
			t.Fatalf("precondition: skill row must win at equal severity, got %s", got.ID)
		}
		assertNamesBothTiers(t, got, "skill", "llm")
	}
}

// AC17, T4.1 direction 2: the LLM row wins because it is strictly more severe;
// the skill row it displaced must still be on the record.
func TestProvenanceOrigins_LLMWinsWhenStrictlyMoreSevere_0074(t *testing.T) {
	skill := deterministicRow("skill-2", model.SeverityMedium)
	llm := llmRow("llm-2", model.SeverityCritical, 0)
	for _, rows := range bothOrders(skill, llm) {
		got := mergeOne(t, rows...)
		if got.ID != "llm-2" {
			t.Fatalf("precondition: a strictly more severe LLM row must win, got %s", got.ID)
		}
		assertNamesBothTiers(t, got, "skill", "llm")
	}
}

// AC17: the whole llm* family is an LLM tier; an L5-verified LLM row that
// collapses into a skill row is recorded under its own provenance value.
func TestProvenanceOrigins_RecordsTheVerifiedLLMValue_0074(t *testing.T) {
	skill := deterministicRow("skill-3", model.SeverityHigh)
	llm := llmRow("llm-3", model.SeverityHigh, 0)
	llm.Provenance = "llm_l5_verified"
	got := mergeOne(t, skill, llm)
	assertNamesBothTiers(t, got, "skill", "llm_l5_verified")
}

// AC17, T4.2 (R23/F5): the commonest both-tier pair is ONE agent's skill row
// and the same agent's LLM row. Origins exclude the winner's own agent and
// cross-agent validation returns early, so today nothing records it.
func TestProvenanceOrigins_SameAgentPairRecordsBothTiers_0074(t *testing.T) {
	skill := provenanceRow("cwe-skill", "cwe", "skill", model.SeverityHigh)
	skill.CheckID = "cwe.sql_injection.string_concat"
	llm := provenanceRow("cwe-llm", "cwe", "llm", model.SeverityHigh)
	for _, rows := range bothOrders(skill, llm) {
		got := mergeOne(t, rows...)
		assertNamesBothTiers(t, got, "skill", "llm")
	}
}

// AC17, T4.3: a row swallowed by a rollup parent contributes its provenance.
func TestProvenanceOrigins_RollupParentRecordsSwallowedTiers_0074(t *testing.T) {
	parent := provenanceRow("rollup", "cwe", "catalog_rollup", model.SeverityHigh)
	parent.IsRollup = true
	parent.InstanceCount = 3
	leafLLM := provenanceRow("leaf-llm", "asvs", "llm", model.SeverityCritical)
	leafSkill := provenanceRow("leaf-skill", "cwe", "skill", model.SeverityHigh)
	out, _ := dedupCrossAgentWithShadow([]model.Finding{leafLLM, parent, leafSkill}, "")
	if len(out) != 1 || !out[0].IsRollup {
		t.Fatalf("precondition: the rollup parent must be the one survivor, got %+v", out)
	}
	assertNamesBothTiers(t, out[0], "catalog_rollup", "llm", "skill")
}

// AC17 negative: two rows that do NOT share a key (LLM line off by 3) are not
// merged, and neither carries a record of the other's tier.
func TestProvenanceOrigins_NoMergeNoBorrowedTier_0074(t *testing.T) {
	skill := deterministicRow("skill-4", model.SeverityHigh)
	llm := llmRow("llm-4", model.SeverityHigh, 0)
	llm.LineStart += 3
	llm.LineEnd += 3
	out, _ := dedupCrossAgentWithShadow([]model.Finding{skill, llm}, "")
	if len(out) != 2 {
		t.Fatalf("rows at different lines must not merge; %d survived", len(out))
	}
	for _, f := range out {
		if got := provenanceOriginsOf(t, f); containsAll(got, "skill", "llm") {
			t.Errorf("unmerged row %s claims both tiers: %v", f.ID, got)
		}
	}
}

// ---------------------------------------------------------------------------
// AC11 / O4 — provenance_origins is never a voter input
// ---------------------------------------------------------------------------

func checkIDs(t *testing.T, f model.Finding) []string {
	t.Helper()
	var checks []struct {
		ID string `json:"id"`
	}
	if raw, ok := f.Validation["checks"]; ok {
		asJSONValue(t, raw, &checks)
	}
	ids := make([]string, 0, len(checks))
	for _, c := range checks {
		ids = append(ids, c.ID)
	}
	return ids
}

func assertNoProvenanceCheck(t *testing.T, f model.Finding) {
	t.Helper()
	for _, id := range checkIDs(t, f) {
		if strings.Contains(strings.ToLower(id), "provenance") {
			t.Errorf("checks[] carries %q: provenance_origins must be a top-level validation key, never a voter input (AC11)", id)
		}
	}
}

// votedRow is a same-agent winner that already carries an agent verdict.
func votedRow(id, provenance string) model.Finding {
	f := provenanceRow(id, "cwe", provenance, model.SeverityHigh)
	f.ValidationStatus = "likely"
	f.ValidationConfidence = 0.7
	f.Validation = map[string]interface{}{
		"status": "likely", "confidence": 0.7,
		"checks": []interface{}{map[string]interface{}{"id": "pattern", "result": "match", "weight": 0.4}},
	}
	return f
}

// AC11: for a same-agent pair (no cross_agent check is appended), recording
// both tiers must leave the verdict and the check list exactly as they were.
func TestProvenanceOrigins_NeverMovesTheVerdict_0074(t *testing.T) {
	skill := votedRow("v-skill", "skill")
	skill.CheckID = "cwe.sql_injection.string_concat"
	llm := votedRow("v-llm", "llm")
	got := mergeOne(t, skill, llm)
	assertNamesBothTiers(t, got, "skill", "llm")
	assertVerdictUnmoved(t, got)
	if ids := checkIDs(t, got); len(ids) != 1 || ids[0] != "pattern" {
		t.Errorf("checks[] changed: %v, want [pattern]", ids)
	}
}

func assertVerdictUnmoved(t *testing.T, got model.Finding) {
	t.Helper()
	if got.ValidationStatus != "likely" || got.ValidationConfidence != 0.7 {
		t.Errorf("verdict moved: status=%q confidence=%v, want likely/0.7", got.ValidationStatus, got.ValidationConfidence)
	}
}

// AC11: a cross-agent pair re-votes (L3 cross_agent), but provenance_origins
// is still top-level and still not a check.
func TestProvenanceOrigins_IsTopLevelOnCrossAgentMerge_0074(t *testing.T) {
	got := mergeOne(t, deterministicRow("x-skill", model.SeverityHigh), llmRow("x-llm", model.SeverityHigh, 0))
	if _, ok := got.Validation["provenance_origins"]; !ok {
		t.Fatalf("validation.provenance_origins missing at top level: %v", got.Validation)
	}
	assertNoProvenanceCheck(t, got)
}

// ---------------------------------------------------------------------------
// AC18 — the loser's reasoning survives, capped
// ---------------------------------------------------------------------------

func describedRow(f model.Finding, desc string) model.Finding {
	f.Description = desc
	return f
}

func mergedTexts(ds []mergedDesc) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.text)
	}
	return out
}

// AC18, T4.4: the LLM's reasoning — what a reviewer acts on — survives a merge
// it lost; the winner's own description is not duplicated into the list.
func TestMergedDescriptions_KeepsTheLoserReasoning_0074(t *testing.T) {
	const reasoning = "uid flows from request.args into the concatenated query without a parameter binding"
	skill := describedRow(deterministicRow("d-skill", model.SeverityHigh), "Pattern match: string-built SQL")
	llm := describedRow(llmRow("d-llm", model.SeverityHigh, 0), reasoning)
	got := mergeOne(t, skill, llm)
	texts := mergedTexts(mergedDescriptionsOf(t, got))
	if !containsAll(texts, reasoning) {
		t.Fatalf("validation.merged_descriptions = %q, want it to keep the losing LLM row's description", texts)
	}
	if containsAll(texts, skill.Description) {
		t.Errorf("the winner's own description must not be copied into merged_descriptions: %q", texts)
	}
}

// AC18: the per-entry cap is 2,048 BYTES, truncation is marked, and a cut
// never splits a UTF-8 rune (the blob is JSON, persisted on both repos).
func TestMergedDescriptions_EntryCappedAndMarked_0074(t *testing.T) {
	long := strings.Repeat("é", 3000) // 6,000 bytes
	got := mergeOne(t,
		describedRow(deterministicRow("c-skill", model.SeverityHigh), "short"),
		describedRow(llmRow("c-llm", model.SeverityHigh, 0), long))
	ds := mergedDescriptionsOf(t, got)
	if len(ds) != 1 {
		t.Fatalf("want one merged description, got %d", len(ds))
	}
	assertCappedEntry(t, ds[0])
}

func assertCappedEntry(t *testing.T, d mergedDesc) {
	t.Helper()
	if len(d.text) > mergedDescEntryCapBytes {
		t.Errorf("entry is %d bytes, cap is %d", len(d.text), mergedDescEntryCapBytes)
	}
	if !d.marksTruncation() {
		t.Errorf("a truncated entry must be marked (flag or marker); got %d bytes unmarked", len(d.text))
	}
	if !utf8.ValidString(d.text) {
		t.Errorf("truncation split a UTF-8 rune")
	}
}

// AC18: an entry under the cap is kept verbatim and not marked.
func TestMergedDescriptions_ShortEntryVerbatim_0074(t *testing.T) {
	const desc = "model reasoning that fits"
	got := mergeOne(t,
		describedRow(deterministicRow("s-skill", model.SeverityHigh), "short"),
		describedRow(llmRow("s-llm", model.SeverityHigh, 0), desc))
	ds := mergedDescriptionsOf(t, got)
	if len(ds) != 1 || ds[0].text != desc || ds[0].truncated {
		t.Errorf("merged_descriptions = %+v, want exactly one untruncated %q", ds, desc)
	}
}

// listTruncationMarked: the row says entries were dropped by some top-level
// merged_descriptions_* key that is true or a positive count.
func listTruncationMarked(v map[string]interface{}) bool {
	for k, val := range v {
		if strings.HasPrefix(k, "merged_descriptions_") && truthy(val) {
			return true
		}
	}
	return false
}

func truthy(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x > 0
	case int:
		return x > 0
	}
	return false
}

// AC18: at most 8 entries per row, and dropping more is marked on the row.
func TestMergedDescriptions_AtMostEightEntriesMarked_0074(t *testing.T) {
	rows := []model.Finding{describedRow(deterministicRow("w", model.SeverityHigh), "winner")}
	for i := 0; i < 10; i++ {
		r := llmRow(fmt.Sprintf("l%02d", i), model.SeverityHigh, 0)
		r.AgentType = fmt.Sprintf("agent%02d", i)
		rows = append(rows, describedRow(r, fmt.Sprintf("distinct reasoning #%d", i)))
	}
	got := mergeOne(t, rows...)
	ds := mergedDescriptionsOf(t, got)
	if len(ds) != mergedDescEntryCapCount {
		t.Errorf("merged_descriptions has %d entries, want the cap of %d", len(ds), mergedDescEntryCapCount)
	}
	if !listTruncationMarked(got.Validation) {
		t.Errorf("10 losers into a cap of 8 must be marked on the row (a merged_descriptions_* key); validation=%v", got.Validation)
	}
}

// ---------------------------------------------------------------------------
// AC22 — the key is untouched (regression pin, T4.8)
// ---------------------------------------------------------------------------

// TestCrossAgentKeyWithRoot_GoldenTable_0074 pins crossAgentKeyWithRoot's
// output byte for byte with a NON-EMPTY root. Golden values were recorded on
// main before P4; P4 adds records beside the key and must never change it.
func TestCrossAgentKeyWithRoot_GoldenTable_0074(t *testing.T) {
	const root = "/srv/app"
	cases := []struct {
		f    model.Finding
		want string
	}{
		{model.Finding{Category: "CWE-89", Title: "SQL injection", FilePath: "/srv/app/src/db.py", LineStart: 42}, "cat:sql-injection|src/db.py|42"},
		{model.Finding{Category: "CWE-89", Title: "SQL injection", FilePath: "src/db.py", LineStart: 42}, "cat:sql-injection|src/db.py|42"},
		{model.Finding{Category: " CWE-80 ", Title: "Reflected XSS", FilePath: "/srv/app/web/view.html", LineStart: 5}, "cat:xss|web/view.html|5"},
		{model.Finding{Category: "A01-broken-access-control", Title: "  Open Redirect ", FilePath: "/srv/app/routes/upload.ts", LineStart: 19}, "cat:A01-broken-access-control|routes/upload.ts|19|open redirect"},
		{model.Finding{Category: "ASVS-V5.1.1", Title: "Input validation", FilePath: "/srv/app/api/h.go", LineStart: 7}, "cat:ASVS-V5.1.1|api/h.go|7"},
		{model.Finding{Category: "", Title: "  Missing Timeout ", FilePath: "/srv/app/client.go", LineStart: 0}, "missing timeout|client.go|0"},
		{model.Finding{Category: "CWE-22", Title: "Path traversal", FilePath: "/elsewhere/lib/fs.go", LineStart: -3}, "cat:path-traversal|/elsewhere/lib/fs.go|-3"},
		{model.Finding{Category: "retry", Title: "No retry", FilePath: "./svc/call.py", LineStart: 1234567}, "cat:retry|svc/call.py|1234567|no retry"},
	}
	for _, c := range cases {
		if got := crossAgentKeyWithRoot(c.f, root); got != c.want {
			t.Errorf("crossAgentKeyWithRoot(%+v) = %q, want %q (AC22: the key must be byte-identical)", c.f, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Replay (T4.9): the synthesized replay serves the two keys as persisted
// ---------------------------------------------------------------------------

// TestReplayCarriesProvenanceOriginsAndMergedDescriptions_0074 is the replay
// third of "write, read and replay" (the repository tests cover the first
// two). A completed audit's synthesized snapshot must carry both keys.
func TestReplayCarriesProvenanceOriginsAndMergedDescriptions_0074(t *testing.T) {
	f := provenanceRow("r-1", "cwe", "skill", model.SeverityHigh)
	f.Validation = map[string]interface{}{
		"status": "likely", "confidence": 0.7, "checks": []interface{}{},
		"provenance_origins":  []interface{}{"skill", "llm"},
		"merged_descriptions": []interface{}{map[string]interface{}{"description": "model reasoning"}},
	}
	audit := &model.Audit{ID: "aud-replay", Types: []string{"cwe"}, Findings: []model.Finding{f}, Scores: map[string]int{}}
	rec := httptest.NewRecorder()
	(&StreamHandler{}).replayCompletedAudit(agui.NewSSEWriter(rec, func() {}), audit)
	body := rec.Body.String()
	for _, key := range []string{`provenance_origins`, `merged_descriptions`, `model reasoning`} {
		if !strings.Contains(body, key) {
			t.Errorf("replayed stream lost %q", key)
		}
	}
}

// ---------------------------------------------------------------------------
// AC19 + version skew — the dedup_buckets log line
// ---------------------------------------------------------------------------

// lockedBuffer is a log sink safe for concurrent writers.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog redirects the standard logger for the rest of the test.
func captureLog(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	flags := log.Flags()
	log.SetOutput(buf)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	})
	return buf
}

// bucketFields returns the key=value fields of the ONE dedup_buckets line for
// (auditID, agent). Zero or several such lines fail the test.
func bucketFields(t *testing.T, logs, auditID, agent string) map[string]string {
	t.Helper()
	var hits []map[string]string
	for _, line := range strings.Split(logs, "\n") {
		if fields := parseBucketLine(line); isBucketFor(fields, auditID, agent) {
			hits = append(hits, fields)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want exactly one dedup_buckets line for audit=%s agent=%s, got %d; log:\n%s", auditID, agent, len(hits), logs)
	}
	return hits[0]
}

func isBucketFor(fields map[string]string, auditID, agent string) bool {
	return fields != nil && fields["agent"] == agent && fields["audit_id"] == auditID
}

// parseBucketLine parses `... dedup_buckets k=v k=v ...`, nil for other lines.
func parseBucketLine(line string) map[string]string {
	idx := strings.Index(line, "dedup_buckets")
	if idx < 0 {
		return nil
	}
	fields := map[string]string{}
	for _, tok := range strings.Fields(line[idx:]) {
		if k, v, ok := strings.Cut(tok, "="); ok {
			fields[k] = v
		}
	}
	return fields
}

// snapRow is one finding row of an agent's result snapshot.
func snapRow(prov, checkID string, line int, sev string) map[string]interface{} {
	return map[string]interface{}{
		"severity": sev, "category": "CWE-89", "title": "SQL injection via " + prov,
		"description": "d", "file_path": "src/db.py", "line_start": line, "line_end": line,
		"recommendation": "r", "provenance": prov, "check_id": checkID,
	}
}

// snapshotEvent renders an agent's result snapshot; counters==nil omits the
// 0074 counters entirely (an older agent).
func snapshotEvent(t *testing.T, agent string, rows []map[string]interface{}, counters map[string]int) *model.AgUIEvent {
	t.Helper()
	payload := map[string]interface{}{"findings": rows, "score": 70, "result_schema": 2}
	for k, v := range counters {
		payload[k] = v
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	return &model.AgUIEvent{Type: model.EventStateSnapshot, AgentType: agent, Snapshot: b}
}

// drainLogs drains every agent's snapshot through the real reducer (and so
// the real cross-agent merge) and returns what it logged.
func drainLogs(t *testing.T, auditID string, evts ...*model.AgUIEvent) string {
	t.Helper()
	logs := captureLog(t)
	drainResultAt(feed(evts), auditID, "", nopSink{})
	return logs.String()
}

func drainBuckets(t *testing.T, auditID string, evt *model.AgUIEvent) map[string]string {
	t.Helper()
	return bucketFields(t, drainLogs(t, auditID, evt), auditID, evt.AgentType)
}

// counters is an agent's 0074 pair as a new agent always sends it.
func counters(emitted, collapsedAgent int) map[string]int {
	return map[string]int{"llm_emitted": emitted, "llm_collapsed_agent": collapsedAgent}
}

// rollupSnapRow is a rollup parent row as an agent's snapshot carries it.
func rollupSnapRow(line int, sev string) map[string]interface{} {
	r := snapRow("catalog_rollup", "", line, sev)
	r["is_rollup"] = true
	r["instance_count"] = 3
	return r
}

// agentBuckets is the expected dedup_buckets line of one agent.
type agentBuckets struct {
	agent string
	want  map[string]string
}

// assertPerAgentBuckets requires exactly ONE line per agent (not one
// aggregate line) and checks each agent's own buckets.
func assertPerAgentBuckets(t *testing.T, logs, auditID string, want ...agentBuckets) {
	t.Helper()
	for _, w := range want {
		assertBuckets(t, bucketFields(t, logs, auditID, w.agent), w.want)
	}
}

// nothingFromLLM is the line of an agent that sent zero LLM rows.
var nothingFromLLM = map[string]string{"emitted": "0", "collapsed_agent": "0", "collapsed_go": "0", "unique": "0", "lost": "0"}

func assertBuckets(t *testing.T, got map[string]string, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("dedup_buckets %s=%q, want %q (line fields %v)", k, got[k], v, got)
		}
	}
}

// AC19, T4.7: every LLM row that reaches Go is unique on the key, so nothing
// is lost: emitted(3) - collapsed_agent(1) - collapsed_go(0) - unique(2) = 0.
func TestDedupBuckets_AllUniqueMeansNothingLost_0074(t *testing.T) {
	rows := []map[string]interface{}{
		snapRow("skill", "cwe.sqli", 10, "high"),
		snapRow("llm", "", 20, "high"),
		snapRow("llm", "", 30, "high"),
	}
	got := drainBuckets(t, "aud-b1", snapshotEvent(t, "cwe", rows, map[string]int{"llm_emitted": 3, "llm_collapsed_agent": 1}))
	assertBuckets(t, got, map[string]string{"emitted": "3", "collapsed_agent": "1", "collapsed_go": "0", "unique": "2", "lost": "0"})
}

// AC19, T4.6: an LLM row that collapses into a skill row at the same site is
// counted in collapsed_go, not lost.
func TestDedupBuckets_CollapseIntoSkillIsCountedNotLost_0074(t *testing.T) {
	rows := []map[string]interface{}{
		snapRow("skill", "cwe.sqli", 10, "high"),
		snapRow("llm", "", 10, "high"),
		snapRow("llm", "", 20, "high"),
	}
	got := drainBuckets(t, "aud-b2", snapshotEvent(t, "cwe", rows, map[string]int{"llm_emitted": 2, "llm_collapsed_agent": 0}))
	assertBuckets(t, got, map[string]string{"emitted": "2", "collapsed_agent": "0", "collapsed_go": "1", "unique": "1", "lost": "0"})
}

// AC19: a loss is reported, never hidden. The agent says it emitted 6 and
// collapsed 1, but only 2 LLM rows arrived: lost = 6 - 1 - 0 - 2 = 3.
func TestDedupBuckets_NonZeroLossIsReported_0074(t *testing.T) {
	rows := []map[string]interface{}{
		snapRow("skill", "cwe.sqli", 10, "high"),
		snapRow("llm", "", 20, "high"),
		snapRow("llm_l5_verified", "", 30, "high"),
	}
	got := drainBuckets(t, "aud-b3", snapshotEvent(t, "cwe", rows, map[string]int{"llm_emitted": 6, "llm_collapsed_agent": 1}))
	assertBuckets(t, got, map[string]string{"emitted": "6", "collapsed_agent": "1", "unique": "2", "lost": "3"})
}

// Version skew (§5.5 item 3): an older agent sends no counters. Its buckets
// are `unavailable`, and lost is NEVER derived from zeros — a derivation
// would report a negative or a false 0.
func TestDedupBuckets_OlderAgentIsUnavailableNeverZero_0074(t *testing.T) {
	rows := []map[string]interface{}{
		snapRow("skill", "cwe.sqli", 10, "high"),
		snapRow("llm", "", 20, "high"),
	}
	got := drainBuckets(t, "aud-b4", snapshotEvent(t, "cwe", rows, nil))
	assertBuckets(t, got, map[string]string{"emitted": "unavailable", "collapsed_agent": "unavailable", "lost": "unavailable"})
}

// Version skew, the other side: a NEW agent that genuinely emitted zero LLM
// rows reports 0, which is a fact and must not be confused with absence.
func TestDedupBuckets_ExplicitZeroIsNotUnavailable_0074(t *testing.T) {
	rows := []map[string]interface{}{snapRow("skill", "cwe.sqli", 10, "high")}
	got := drainBuckets(t, "aud-b5", snapshotEvent(t, "cwe", rows, map[string]int{"llm_emitted": 0, "llm_collapsed_agent": 0}))
	assertBuckets(t, got, map[string]string{"emitted": "0", "collapsed_agent": "0", "collapsed_go": "0", "unique": "0", "lost": "0"})
}

// ---------------------------------------------------------------------------
// AC19 across agents — collapsed_go is charged to the LLM row's OWN agent
// ---------------------------------------------------------------------------
//
// The bucket an LLM row lands in is decided by what happened to THAT row:
//   - it survived the Go merge (as the winner of its key, or alone) -> unique;
//   - it was merged INTO another row, whatever that row's agent or tier
//     (skill, another agent's LLM row, a rollup parent) -> collapsed_go;
// and it is charged to the agent that EMITTED it, never to the winner's agent.
// A row merged away is not lost: lost counts only rows that vanished, so
// lost == 0 in every fixture below.

// AC19: an asvs LLM row collapsing into a cwe skill row is asvs's
// collapsed_go. The cwe agent sent no LLM rows, so its own line is all zero;
// charging the collapse to the winner's agent would read cwe collapsed_go=1.
func TestDedupBuckets_CrossAgentCollapseChargedToTheLLMRowsAgent_0074(t *testing.T) {
	cwe := snapshotEvent(t, "cwe", []map[string]interface{}{snapRow("skill", "cwe.sqli", 10, "high")}, counters(0, 0))
	asvs := snapshotEvent(t, "asvs", []map[string]interface{}{
		snapRow("llm", "", 10, "high"),
		snapRow("llm", "", 20, "high"),
	}, counters(2, 0))
	logs := drainLogs(t, "aud-x1", cwe, asvs)
	assertPerAgentBuckets(t, logs, "aud-x1",
		agentBuckets{"cwe", nothingFromLLM},
		agentBuckets{"asvs", map[string]string{"emitted": "2", "collapsed_agent": "0", "collapsed_go": "1", "unique": "1", "lost": "0"}})
}

// AC19: an LLM row merged into ANOTHER agent's LLM row is collapsed_go, not
// lost (the plan's "llm_collapsed_into_skill" wording must not exclude it).
// The strictly more severe cwe row wins; the asvs row is merged into it.
func TestDedupBuckets_LLMIntoAnotherAgentsLLMRowIsCollapsedNotLost_0074(t *testing.T) {
	cwe := snapshotEvent(t, "cwe", []map[string]interface{}{snapRow("llm", "", 10, "critical")}, counters(1, 0))
	asvs := snapshotEvent(t, "asvs", []map[string]interface{}{snapRow("llm", "", 10, "high")}, counters(1, 0))
	logs := drainLogs(t, "aud-x2", asvs, cwe)
	assertPerAgentBuckets(t, logs, "aud-x2",
		agentBuckets{"cwe", map[string]string{"emitted": "1", "collapsed_go": "0", "unique": "1", "lost": "0"}},
		agentBuckets{"asvs", map[string]string{"emitted": "1", "collapsed_go": "1", "unique": "0", "lost": "0"}})
}

// AC19, LLM-wins direction: a strictly more severe LLM row that absorbs a
// skill row is the survivor of its key, so it is unique — not collapsed_go,
// and never a false lost=1. The displaced skill row is not an LLM row and
// moves no bucket of its own agent.
func TestDedupBuckets_LLMRowThatWinsIsUnique_0074(t *testing.T) {
	cwe := snapshotEvent(t, "cwe", []map[string]interface{}{snapRow("skill", "cwe.sqli", 10, "medium")}, counters(0, 0))
	asvs := snapshotEvent(t, "asvs", []map[string]interface{}{snapRow("llm", "", 10, "critical")}, counters(1, 0))
	logs := drainLogs(t, "aud-x3", cwe, asvs)
	assertPerAgentBuckets(t, logs, "aud-x3",
		agentBuckets{"cwe", nothingFromLLM},
		agentBuckets{"asvs", map[string]string{"emitted": "1", "collapsed_go": "0", "unique": "1", "lost": "0"}})
}

// AC19, LLM-wins direction within ONE agent: the same rule holds when the
// displaced skill row is the LLM row's own agent's.
func TestDedupBuckets_SameAgentLLMWinIsUnique_0074(t *testing.T) {
	rows := []map[string]interface{}{
		snapRow("skill", "cwe.sqli", 10, "medium"),
		snapRow("llm", "", 10, "critical"),
	}
	got := drainBuckets(t, "aud-x4", snapshotEvent(t, "cwe", rows, counters(1, 0)))
	assertBuckets(t, got, map[string]string{"emitted": "1", "collapsed_go": "0", "unique": "1", "lost": "0"})
}

// AC19, T4.3: an LLM leaf swallowed by a rollup parent (another agent's) is
// collapsed_go for the leaf's agent; the parent is not an LLM row.
func TestDedupBuckets_LLMLeafUnderRollupParentIsCollapsed_0074(t *testing.T) {
	cwe := snapshotEvent(t, "cwe", []map[string]interface{}{rollupSnapRow(10, "high")}, counters(0, 0))
	asvs := snapshotEvent(t, "asvs", []map[string]interface{}{snapRow("llm", "", 10, "critical")}, counters(1, 0))
	logs := drainLogs(t, "aud-x5", asvs, cwe)
	assertPerAgentBuckets(t, logs, "aud-x5",
		agentBuckets{"cwe", nothingFromLLM},
		agentBuckets{"asvs", map[string]string{"emitted": "1", "collapsed_go": "1", "unique": "0", "lost": "0"}})
}

// AC19, plan §8 negative row: an LLM row whose line is off by 3 from the
// skill row does not merge, so it is unique and nothing is lost.
func TestDedupBuckets_OffByThreeIsUniqueNotLost_0074(t *testing.T) {
	rows := []map[string]interface{}{
		snapRow("skill", "cwe.sqli", 10, "high"),
		snapRow("llm", "", 13, "high"),
	}
	got := drainBuckets(t, "aud-x6", snapshotEvent(t, "cwe", rows, counters(1, 0)))
	assertBuckets(t, got, map[string]string{"emitted": "1", "collapsed_go": "0", "unique": "1", "lost": "0"})
}

// ---------------------------------------------------------------------------
// AC11 / O4 across agents — both tiers never move the re-vote
// ---------------------------------------------------------------------------

// votedSkillWinner is the cwe skill row that wins either pair below, carrying
// an agent verdict so the L3 cross_agent re-vote has something to move.
func votedSkillWinner() model.Finding {
	f := deterministicRow("o4-skill", model.SeverityHigh)
	f.ValidationStatus = "likely"
	f.ValidationConfidence = 0.7
	f.Validation = map[string]interface{}{
		"status": "likely", "confidence": 0.7,
		"checks": []interface{}{map[string]interface{}{"id": "pattern", "result": "match", "weight": 0.4}},
	}
	return f
}

// verdictOf projects everything a voter decides or reads, through JSON.
func verdictOf(t *testing.T, f model.Finding) string {
	t.Helper()
	b, err := json.Marshal([]interface{}{f.ValidationStatus, f.ValidationConfidence,
		f.Validation["status"], f.Validation["confidence"], f.Validation["checks"]})
	if err != nil {
		t.Fatalf("marshal verdict: %v", err)
	}
	return string(b)
}

// AC11/O4: a cross-agent skill+LLM merge re-votes EXACTLY as the otherwise
// identical skill+skill merge (same agents, same severities). Both tiers are
// recorded, but the cross_agent weight, its extras and the re-voted
// confidence must not depend on the loser's tier.
func TestProvenanceOrigins_CrossAgentVerdictEqualsSkillOnlyPair_0074(t *testing.T) {
	llmLoser := llmRow("o4-asvs", model.SeverityHigh, 0)
	skillLoser := llmLoser
	skillLoser.Provenance = "skill"
	withLLM := mergeOne(t, votedSkillWinner(), llmLoser)
	skillOnly := mergeOne(t, votedSkillWinner(), skillLoser)
	assertNamesBothTiers(t, withLLM, "skill", "llm")
	if a, b := verdictOf(t, withLLM), verdictOf(t, skillOnly); a != b {
		t.Errorf("the LLM tier moved the cross-agent re-vote:\n skill+llm   %s\n skill+skill %s", a, b)
	}
}

// ---------------------------------------------------------------------------
// AC18, LLM-wins direction — the displaced skill row's description survives
// ---------------------------------------------------------------------------

func TestMergedDescriptions_LLMWinsKeepsTheSkillDescription_0074(t *testing.T) {
	const skillDesc = "Pattern match: string-built SQL passed to cursor.execute"
	skill := describedRow(deterministicRow("dw-skill", model.SeverityMedium), skillDesc)
	llm := describedRow(llmRow("dw-llm", model.SeverityCritical, 0), "model reasoning that won")
	for _, rows := range bothOrders(skill, llm) {
		got := mergeOne(t, rows...)
		if got.ID != "dw-llm" {
			t.Fatalf("precondition: a strictly more severe LLM row must win, got %s", got.ID)
		}
		assertKeepsOnlyTheLoser(t, got, skillDesc, llm.Description)
	}
}

func assertKeepsOnlyTheLoser(t *testing.T, got model.Finding, loserDesc, winnerDesc string) {
	t.Helper()
	texts := mergedTexts(mergedDescriptionsOf(t, got))
	if !containsAll(texts, loserDesc) || containsAll(texts, winnerDesc) {
		t.Errorf("merged_descriptions = %q, want the displaced row's description and not the winner's own", texts)
	}
}
