package agui

// 0074 verification item 1: the result snapshot is forwarded to live SSE
// clients and the broadcast replay before Go persists anything. A snapshot that
// does not declare merged_llm_masked carries an older agent's unmasked merge
// descriptions; their token shapes are masked here, at the one point both the
// live stream and persistence read. A masking agent's bytes pass untouched.
// The raw payload is never logged. Synthetic values.

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
)

const scrubJWT0074 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

func resultWithMergedLLM(marked bool) json.RawMessage {
	env := map[string]any{
		"findings": []any{map[string]any{
			"title": "SQL injection", "provenance": "skill",
			"merged_llm": []any{map[string]any{"provenance": "llm", "description": "token " + scrubJWT0074}},
		}},
	}
	if marked {
		env["merged_llm_masked"] = true
	}
	b, _ := json.Marshal(env)
	return b
}

func snapshotOf(t *testing.T, data json.RawMessage) json.RawMessage {
	t.Helper()
	evts, err := translateResult("cwe", data)
	if err != nil {
		t.Fatal(err)
	}
	return evts[len(evts)-1].Snapshot
}

func TestTranslateResult_MasksUnmarkedMergedLLM_0074(t *testing.T) {
	snap := string(snapshotOf(t, resultWithMergedLLM(false)))
	if strings.Contains(snap, scrubJWT0074) {
		t.Fatalf("an unmarked snapshot forwarded a raw token: %s", snap)
	}
	if !strings.Contains(snap, `"provenance":"llm"`) || !strings.Contains(snap, "***REDACTED***") {
		t.Errorf("the merge record must survive, masked: %s", snap)
	}
}

func TestTranslateResult_MarkedSnapshotIsForwardedVerbatim_0074(t *testing.T) {
	in := resultWithMergedLLM(true)
	if out := snapshotOf(t, in); !bytes.Equal(out, in) {
		t.Errorf("a masking agent's snapshot was rewritten:\n in=%s\nout=%s", in, out)
	}
}

func TestTranslateResult_NeverLogsThePayload_0074(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	snapshotOf(t, resultWithMergedLLM(true))
	if strings.Contains(buf.String(), "eyJ") || strings.Contains(buf.String(), "merged_llm") {
		t.Errorf("the result payload reached the log: %s", buf.String())
	}
}

// Re-audit finding 2: the live stream applies the same redaction persistence
// does, so a prose secret (not token-shaped) is masked there too.
func TestTranslateResult_MasksUnmarkedProseSecrets_0074(t *testing.T) {
	env := map[string]any{"findings": []any{map[string]any{"title": "x", "merged_llm": []any{
		map[string]any{"provenance": "llm", "description": `the code sets password = "hunter2butlonger" here`}}}}}
	b, _ := json.Marshal(env)
	if snap := string(snapshotOf(t, b)); strings.Contains(snap, "hunter2butlonger") {
		t.Errorf("a prose secret reached the live snapshot: %s", snap)
	}
}
