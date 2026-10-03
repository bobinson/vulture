package handler

// Feature 0074 P5 / T5.3 / AC19 — the Go half of "flipping
// VULTURE_LLM_QUOTE_REANCHOR loses no LLM row".
//
// The agent-side collapse key is (check_id or normalised title, path) and has
// no line in it, so a re-anchor cannot change what collapses there. Go's
// cross-agent key (crossAgentKeyWithRoot) DOES carry the line, so this is the
// site where the flip can create a collision that did not exist before:
// the model cites line 12, the quote is verified on line 27, and line 27 is
// exactly where a skill row already sits, under the same canonical path and
// the same CWE family.
//
// The agent re-anchors before Go ever sees the row, so "REANCHOR off" and
// "REANCHOR on" are, to Go, the same LLM row arriving at its claimed line and
// at its verified line. Both must account for every emitted row:
//
//	emitted == collapsed_agent + collapsed_go + unique, and lost == 0
//
// with the post-move collision landing in collapsed_go (the plan's
// "llm_collapsed_into_skill"), never in lost.
//
// The path forms differ on purpose: the skill tier reports the absolute path
// it walked, the LLM tier the relative one the prompt showed. The collision
// only exists after canonicalising against the source root, which is the
// realistic shape. Every fixture is synthetic.

import (
	"strconv"
	"testing"

	"github.com/vulture/backend/internal/model"
)

const (
	flipRoot        = "/srv/app"
	flipClaimedLine = 12
	flipVerified    = 27
)

// flipSkillRow is the deterministic row at the verified site (absolute path).
func flipSkillRow() map[string]interface{} {
	r := snapRow("skill", "cwe.os_command.shell_concat", flipVerified, "high")
	r["category"] = "CWE-78"
	r["file_path"] = flipRoot + "/src/app.py"
	return r
}

// flipLLMRow is the model's row at `line` (relative path, same CWE family:
// CWE-77 and CWE-78 share the os-command-injection group).
func flipLLMRow(line int) map[string]interface{} {
	r := snapRow("llm", "", line, "high")
	r["category"] = "CWE-77"
	r["file_path"] = "src/app.py"
	return r
}

// drainAt drains the snapshots through the real reducer WITH a source root,
// returning the surviving findings and what was logged.
func drainAt(t *testing.T, auditID string, evts ...*model.AgUIEvent) ([]model.Finding, string) {
	t.Helper()
	logs := captureLog(t)
	res := drainResultAt(feed(evts), auditID, flipRoot, nopSink{})
	return res.Findings, logs.String()
}

// flipCase is one side of the flip, as Go receives it.
type flipCase struct {
	name      string
	llmLine   int
	survivors int
	want      map[string]string
}

var flipCases = []flipCase{
	{"REANCHOR off: claimed line, no collision", flipClaimedLine, 2,
		map[string]string{"emitted": "1", "collapsed_agent": "0", "collapsed_go": "0", "unique": "1", "lost": "0"}},
	{"REANCHOR on: verified line collides with the skill row", flipVerified, 1,
		map[string]string{"emitted": "1", "collapsed_agent": "0", "collapsed_go": "1", "unique": "0", "lost": "0"}},
}

// assertAccounted checks the AC19 identity on one dedup_buckets line.
func assertAccounted(t *testing.T, got map[string]string) {
	t.Helper()
	sum := atoiField(t, got, "collapsed_agent") + atoiField(t, got, "collapsed_go") + atoiField(t, got, "unique")
	if emitted := atoiField(t, got, "emitted"); emitted != sum {
		t.Errorf("AC19: emitted=%d != collapsed_agent+collapsed_go+unique=%d (fields %v)", emitted, sum, got)
	}
}

func atoiField(t *testing.T, fields map[string]string, k string) int {
	t.Helper()
	n, err := strconv.Atoi(fields[k])
	if err != nil {
		t.Fatalf("dedup_buckets %s=%q is not an integer (fields %v)", k, fields[k], fields)
	}
	return n
}

// T5.3 / AC19, cross-agent: a cwe skill row and an asvs LLM row.
func TestReanchorFlip_CrossAgentCollisionIsCountedNotLost_0074(t *testing.T) {
	for i, c := range flipCases {
		t.Run(c.name, func(t *testing.T) {
			auditID := "aud-flip-x" + strconv.Itoa(i)
			cwe := snapshotEvent(t, "cwe", []map[string]interface{}{flipSkillRow()}, counters(0, 0))
			asvs := snapshotEvent(t, "asvs", []map[string]interface{}{flipLLMRow(c.llmLine)}, counters(1, 0))
			kept, logs := drainAt(t, auditID, cwe, asvs)
			if len(kept) != c.survivors {
				t.Fatalf("precondition: fixture must yield %d survivors at line %d, got %d", c.survivors, c.llmLine, len(kept))
			}
			got := bucketFields(t, logs, auditID, "asvs")
			assertBuckets(t, got, c.want)
			assertAccounted(t, got)
		})
	}
}

// T5.3 / AC19, same agent: the commonest pair is ONE agent's skill row and
// its own LLM row (R23/F5), both in a single snapshot.
func TestReanchorFlip_SameAgentCollisionIsCountedNotLost_0074(t *testing.T) {
	for i, c := range flipCases {
		t.Run(c.name, func(t *testing.T) {
			auditID := "aud-flip-s" + strconv.Itoa(i)
			rows := []map[string]interface{}{flipSkillRow(), flipLLMRow(c.llmLine)}
			kept, logs := drainAt(t, auditID, snapshotEvent(t, "cwe", rows, counters(1, 0)))
			if len(kept) != c.survivors {
				t.Fatalf("precondition: fixture must yield %d survivors at line %d, got %d", c.survivors, c.llmLine, len(kept))
			}
			got := bucketFields(t, logs, auditID, "cwe")
			assertBuckets(t, got, c.want)
			assertAccounted(t, got)
		})
	}
}

// T5.3 / AC17 under the flip: the row the move collapsed away is still on
// the record, so a reviewer can see that the LLM tier found it too.
func TestReanchorFlip_CollapsedRowStaysOnTheRecord_0074(t *testing.T) {
	cwe := snapshotEvent(t, "cwe", []map[string]interface{}{flipSkillRow()}, counters(0, 0))
	asvs := snapshotEvent(t, "asvs", []map[string]interface{}{flipLLMRow(flipVerified)}, counters(1, 0))
	kept, _ := drainAt(t, "aud-flip-r", cwe, asvs)
	if len(kept) != 1 {
		t.Fatalf("precondition: the verified line must collide, got %d survivors", len(kept))
	}
	assertNamesBothTiers(t, kept[0], "skill", "llm")
}
