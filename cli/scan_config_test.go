package main

import (
	"encoding/json"
	"testing"
)

// Feature 0083 I6 — the JSON config body must be byte-identical for every
// flag combination expressible BEFORE 0083.
//
// parseScanFlags returned 7 positional values while cmdScan took 9 parameters
// in a DIFFERENT order (ci moved from last to 7th). Adding --no-llm and
// --validate-llm-batch-size gives four adjacent bools and two adjacent ints; a
// transposition would compile, vet clean, and pass the old suite. This table is
// the guard, and it is checked for non-vacuity below.

type goldenCase struct {
	name string
	in   scanFlags
	want string // canonical JSON of the config map, "" = no config key emitted
}

func preO83Cases() []goldenCase {
	return []goldenCase{
		{"bare", scanFlags{}, ""},
		{"fresh", scanFlags{fresh: true, noCache: true}, `{"fresh":true}`},
		{"tier3", scanFlags{tier3: true}, `{"llm_tier3":true}`},
		{"validate", scanFlags{validateLLM: true}, `{"validate":{"llm":true}}`},
		{"validate+topn", scanFlags{validateLLM: true, validateLLMTopN: 40},
			`{"validate":{"llm":true,"llm_top_n":40}}`},
		// DELIBERATELY NOT PINNED: pre-0083, `--validate-llm-top-n 40` without
		// `--validate-llm` emitted no config at all, because the whole validate
		// block was gated on `if validateLLM`. That is the defect, not the
		// contract — on the deployment shape env.example recommends
		// (VULTURE_USE_VALIDATE_LLM=true, judge always on) the operator has no
		// reason to pass --validate-llm and every reason to cap the population.
		// The new behaviour is pinned in TestBuildScanConfigNewFlags.
		{"fresh+tier3", scanFlags{fresh: true, noCache: true, tier3: true},
			`{"fresh":true,"llm_tier3":true}`},
		{"validate+fresh", scanFlags{validateLLM: true, fresh: true, noCache: true},
			`{"fresh":true,"validate":{"llm":true}}`},
		{"validate+tier3", scanFlags{validateLLM: true, tier3: true},
			`{"llm_tier3":true,"validate":{"llm":true}}`},
		{"types only emits no config", scanFlags{types: []string{"cwe"}}, ""},
		{"all three pre-0083", scanFlags{fresh: true, noCache: true, tier3: true, validateLLM: true, validateLLMTopN: 5},
			`{"fresh":true,"llm_tier3":true,"validate":{"llm":true,"llm_top_n":5}}`},
	}
}

func canon(t *testing.T, m map[string]interface{}) string {
	t.Helper()
	if len(m) == 0 {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestBuildScanConfigGolden(t *testing.T) {
	cases := preO83Cases()

	// NON-VACUITY (a): enough rows.
	if len(cases) < 8 {
		t.Fatalf("golden table must have >=8 rows, got %d", len(cases))
	}
	// NON-VACUITY (b): at least one row must expect a NON-empty body, or the
	// whole table would pass against a buildScanConfig that returns nil.
	nonEmpty := 0
	for _, c := range cases {
		if c.want != "" {
			nonEmpty++
		}
	}
	if nonEmpty < 5 {
		t.Fatalf("golden table needs >=5 non-empty expectations, got %d", nonEmpty)
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := canon(t, buildScanConfig(c.in)); got != c.want {
				t.Errorf("config drifted\n  got  %s\n  want %s", got, c.want)
			}
		})
	}
}

// ---- feature 0083's own additions -------------------------------------------

func TestBuildScanConfigNewFlags(t *testing.T) {
	for _, c := range []goldenCase{
		{"no-llm alone", scanFlags{noLLM: true, noCache: true}, `{"use_llm":false}`},
		{"the headline: skills + judge",
			scanFlags{noLLM: true, noCache: true, validateLLM: true},
			`{"use_llm":false,"validate":{"llm":true}}`},
		{"batch size reaches the validate block",
			scanFlags{validateLLM: true, validateLLMBatchSize: 3},
			`{"validate":{"llm":true,"llm_batch_size":3}}`},
		{"top-n now emits even without --validate-llm",
			scanFlags{validateLLMTopN: 40}, `{"validate":{"llm_top_n":40}}`},
		{"batch size without --validate-llm also emits",
			scanFlags{validateLLMBatchSize: 3}, `{"validate":{"llm_batch_size":3}}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := canon(t, buildScanConfig(c.in)); got != c.want {
				t.Errorf("\n  got  %s\n  want %s", got, c.want)
			}
		})
	}
}
