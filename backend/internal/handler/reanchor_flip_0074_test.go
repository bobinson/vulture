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

// flipPair is how the skill row and the LLM row reach Go: agent names the
// agent whose dedup_buckets line carries the LLM row.
type flipPair struct {
	name, agent string
	events      func(t *testing.T, llmLine int) []*model.AgUIEvent
}

var flipPairs = []flipPair{
	// cross-agent: a cwe skill row and an asvs LLM row.
	{"cross-agent", "asvs", func(t *testing.T, line int) []*model.AgUIEvent {
		return []*model.AgUIEvent{
			snapshotEvent(t, "cwe", []map[string]interface{}{flipSkillRow()}, counters(0, 0)),
			snapshotEvent(t, "asvs", []map[string]interface{}{flipLLMRow(line)}, counters(1, 0)),
		}
	}},
	// same agent: the commonest pair is ONE agent's skill row and its own LLM
	// row (R23/F5), both in a single snapshot.
	{"same-agent", "cwe", func(t *testing.T, line int) []*model.AgUIEvent {
		rows := []map[string]interface{}{flipSkillRow(), flipLLMRow(line)}
		return []*model.AgUIEvent{snapshotEvent(t, "cwe", rows, counters(1, 0))}
	}},
}

// T5.3 / AC19: each side of the flip, for each pair shape, accounts for every
// emitted row (the exact want maps pin emitted == collapsed_agent +
// collapsed_go + unique and lost == 0).
func TestReanchorFlip_CollisionIsCountedNotLost_0074(t *testing.T) {
	for _, p := range flipPairs {
		for i, c := range flipCases {
			t.Run(p.name+"/"+c.name, func(t *testing.T) {
				assertFlip(t, p, c, "aud-flip-"+p.agent+strconv.Itoa(i))
			})
		}
	}
}

// assertFlip drains one pair at the case's line and checks the survivors,
// that — T5.3 / AC17 under the flip — a row the move collapsed away is still
// on the record (a reviewer can see the LLM tier found it too), and the LLM
// row's agent's buckets.
func assertFlip(t *testing.T, p flipPair, c flipCase, auditID string) {
	t.Helper()
	kept, logs := drainAt(t, auditID, p.events(t, c.llmLine)...)
	if len(kept) != c.survivors {
		t.Fatalf("precondition: fixture must yield %d survivors at line %d, got %d", c.survivors, c.llmLine, len(kept))
	}
	if c.survivors == 1 {
		assertNamesBothTiers(t, kept[0], "skill", "llm")
	}
	assertBuckets(t, bucketFields(t, logs, auditID, p.agent), c.want)
}
