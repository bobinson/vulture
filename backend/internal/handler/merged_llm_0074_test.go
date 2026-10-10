package handler

// Feature 0074 contract C3: a same-agent skill/LLM pair collapses INSIDE the
// agent, before Go sees it. The agent then sends the surviving row with
// `merged_llm` (the dropped LLM rows' provenance and description), and the
// cross-agent merge folds it into validation.provenance_origins and
// validation.merged_descriptions exactly as if Go had merged the pair itself.
// merged_llm is a wire field only: it never survives the merge.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

const agentMergedReasoning = "uid flows from request.args into a string-built SELECT"

func withMergedLLM(f model.Finding, rows ...model.MergedLLMRow) model.Finding {
	f.MergedLLM = rows
	return f
}

// The agent-collapsed pair reaches Go as ONE row: alone in the run it must
// still name both tiers and keep the LLM reasoning.
func TestMergedLLM_SoloSurvivorNamesBothTiers_0074(t *testing.T) {
	skill := withMergedLLM(deterministicRow("m-skill", model.SeverityHigh),
		model.MergedLLMRow{Provenance: "llm", Description: agentMergedReasoning})
	got := mergeOne(t, skill)
	assertNamesBothTiers(t, got, "skill", "llm")
	assertKeepsOnlyTheLoser(t, got, agentMergedReasoning, skill.Description)
	assertNoMergedLLM(t, got)
}

// With an unrelated second row in the run (no cross-agent merge for the
// survivor's key) the fold still happens.
func TestMergedLLM_UnmergedSurvivorAmongOthers_0074(t *testing.T) {
	skill := withMergedLLM(deterministicRow("m2-skill", model.SeverityHigh),
		model.MergedLLMRow{Provenance: "llm_l5_verified", Description: agentMergedReasoning})
	other := deterministicRow("m2-other", model.SeverityHigh)
	other.LineStart += 50
	other.LineEnd += 50
	out, _ := dedupCrossAgentWithShadow([]model.Finding{skill, other}, "")
	if len(out) != 2 {
		t.Fatalf("precondition: 2 unmerged rows, got %d", len(out))
	}
	assertNamesBothTiers(t, out[0], "skill", "llm_l5_verified")
	if got := provenanceOriginsOf(t, out[1]); len(got) != 0 {
		t.Errorf("a row with no merges must not carry provenance_origins: %v", got)
	}
}

// Merged into another agent's row, the agent-side merges are folded too.
func TestMergedLLM_FoldedThroughCrossAgentMerge_0074(t *testing.T) {
	skill := withMergedLLM(deterministicRow("m3-skill", model.SeverityHigh),
		model.MergedLLMRow{Provenance: "llm", Description: agentMergedReasoning})
	other := withProvenance(deterministicRow("m3-semgrep", model.SeverityHigh), "semgrep")
	other.AgentType = "semgrep"
	for _, rows := range bothOrders(skill, other) {
		got := mergeOne(t, rows...)
		assertNamesBothTiers(t, got, "skill", "semgrep", "llm")
		if !containsAll(mergedTexts(mergedDescriptionsOf(t, got)), agentMergedReasoning) {
			t.Errorf("agent-merged reasoning lost through the cross-agent merge: %v", got.Validation["merged_descriptions"])
		}
		assertNoMergedLLM(t, got)
	}
}

// The per-entry cap and the entry count cap apply to folded entries.
func TestMergedLLM_CapsApply_0074(t *testing.T) {
	rows := make([]model.MergedLLMRow, 0, mergedDescEntryCapCount+3)
	for i := 0; i < mergedDescEntryCapCount+3; i++ {
		rows = append(rows, model.MergedLLMRow{Provenance: "llm", Description: strings.Repeat(string(rune('a'+i)), 3000)})
	}
	got := mergeOne(t, withMergedLLM(deterministicRow("m4-skill", model.SeverityHigh), rows...))
	ds := mergedDescriptionsOf(t, got)
	if len(ds) != mergedDescEntryCapCount {
		t.Fatalf("%d entries, want the cap %d", len(ds), mergedDescEntryCapCount)
	}
	assertCappedEntry(t, ds[0])
	if !listTruncationMarked(got.Validation) {
		t.Errorf("dropped entries are not counted: %v", got.Validation)
	}
}

// merged_llm crosses the wire inbound only; a merged row never carries it out.
func assertNoMergedLLM(t *testing.T, f model.Finding) {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "merged_llm") {
		t.Errorf("merged_llm survived the merge: %s", b)
	}
}

// The agent sends merged_llm on the wire; it decodes into the finding.
func TestMergedLLM_DecodesFromTheAgentWire_0074(t *testing.T) {
	var f model.Finding
	raw := `{"title":"t","provenance":"skill","merged_llm":[{"provenance":"llm","description":"why"}]}`
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(f.MergedLLM) != 1 || f.MergedLLM[0].Provenance != "llm" || f.MergedLLM[0].Description != "why" {
		t.Fatalf("merged_llm did not decode: %+v", f.MergedLLM)
	}
}

// #15: a secret-bearing finding's displaced description is redacted with the
// agent's line redactor before it is persisted.
func TestMergedDescriptions_SecretBearingRedacted_0074(t *testing.T) {
	const secret = "AKIA1234567890SECRET"
	leak := `The key is hard-coded: api_key = "` + secret + `"`
	skill := deterministicRow("r-skill", model.SeverityHigh)
	skill.Category = "CWE-798"
	llm := describedRow(llmRow("r-llm", model.SeverityHigh, 0), leak)
	llm.Category = "CWE-798"
	viaAgent := withMergedLLM(deterministicRow("r2-skill", model.SeverityHigh),
		model.MergedLLMRow{Provenance: "llm", Description: leak})
	viaAgent.Category = "CWE-798"
	for _, got := range []model.Finding{mergeOne(t, skill, llm), mergeOne(t, viaAgent)} {
		md := validationStrings(t, got.Validation["merged_descriptions"])
		if strings.Contains(md, secret) || !strings.Contains(md, "REDACTED") {
			t.Errorf("secret-bearing merged description not redacted: %s", md)
		}
	}
}

func validationStrings(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// Re-audit #15: a secret is not confined to secret-bearing CWEs. Any
// category's displaced description has its prose secrets (a named secret's
// value, a key-shaped token) masked on persist, while ordinary prose —
// quoted identifiers, apostrophes — is kept verbatim outside them.
func TestMergedDescriptions_ProseSecretsRedactedInAnyCategory_0074(t *testing.T) {
	const desc = "SQL built from 'uid'; it's reachable. Found password: hunter2 and key sk-live-ABCDEF0123456789"
	const want = "SQL built from 'uid'; it's reachable. Found password: ***REDACTED*** and key ***REDACTED***"
	row := withMergedLLM(deterministicRow("r3-skill", model.SeverityHigh),
		model.MergedLLMRow{Provenance: "llm", Description: desc})
	row.Category = "CWE-89"
	ds := mergedDescriptionsOf(t, mergeOne(t, row))
	if len(ds) != 1 || ds[0].text != want {
		t.Fatalf("merged description = %v, want %q", ds, want)
	}
}

// Contract T3: the agent caps merged_llm itself and sends the count of the
// distinct descriptions it refused as merged_llm_dropped; Go adds it to
// validation.merged_descriptions_dropped, so the count does not undercount
// when the agent's cap fired, and never persists the wire field.
func TestMergedLLM_AgentDropCountIsAdded_0074(t *testing.T) {
	rows := []model.MergedLLMRow{
		{Provenance: "llm", Description: "first"},
		{Provenance: "llm_l5_verified", Description: ""},
	}
	skill := withMergedLLM(deterministicRow("m5-skill", model.SeverityHigh), rows...)
	skill.MergedLLMDropped = 5
	got := mergeOne(t, skill)
	if n, _ := got.Validation["merged_descriptions_dropped"].(int); n != 5 {
		t.Errorf("merged_descriptions_dropped = %v, want the agent's 5", got.Validation["merged_descriptions_dropped"])
	}
	if ds := mergedDescriptionsOf(t, got); len(ds) != 1 {
		t.Errorf("a description-less entry must not become a merged description: %v", ds)
	}
	assertNamesBothTiers(t, got, "skill", "llm", "llm_l5_verified")
	assertNoMergedLLM(t, got)
}

// A row whose agent refused every description at the cap still folds.
func TestMergedLLM_DropCountAloneFolds_0074(t *testing.T) {
	skill := deterministicRow("m6-skill", model.SeverityHigh)
	skill.MergedLLMDropped = 2
	got := mergeOne(t, skill)
	if n, _ := got.Validation["merged_descriptions_dropped"].(int); n != 2 {
		t.Errorf("merged_descriptions_dropped = %v, want 2", got.Validation["merged_descriptions_dropped"])
	}
	assertNoMergedLLM(t, got)
}

func TestMergedLLM_DropCountDecodesFromTheAgentWire_0074(t *testing.T) {
	var f model.Finding
	if err := json.Unmarshal([]byte(`{"title":"t","merged_llm_dropped":7}`), &f); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.MergedLLMDropped != 7 {
		t.Fatalf("merged_llm_dropped did not decode: %d", f.MergedLLMDropped)
	}
}
