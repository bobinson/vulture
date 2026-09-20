package agui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 §6.1 — the Go half of the cross-language wire pin.
//
// WHY A SHARED FIXTURE AND NOT A GO-LOCAL ONE. The failure this guards is
// SILENT in both directions. `ParseScanOutcome` unmarshals into a struct with
// no DisallowUnknownFields, so if the Python agent renamed `lineage_checks` to
// anything else the parser would keep returning an empty slice — no error, no
// log line — and the closure pass would read "the agent answered nothing"
// about every row it asked about, degrading each one to `unconfirmed` on every
// scan. Symmetrically, renaming a key on the Go request side would leave the
// agent reading a row with an empty `rel_path` and answering `unconfirmable`.
// A fixture that only Go asserts against cannot see either case: it would be
// renamed in the same commit as the code.
//
// So one file is asserted against by two suites, in two languages:
//
//	agents/shared/tests/contract/0091_lineage_wire.json
//	agents/shared/tests/e2e/test_0091_wire_seam.py   (the Python half)
//
// This test reads that file rather than a copy under testdata/, deliberately:
// a copy is the same thing as a Go-local fixture.

// wireContractPath resolves the shared contract file from this package's
// directory. Hard failure — never a skip — when it is missing: a pin that
// quietly stops running is worse than no pin, because the report still says
// green.
func wireContractPath(t *testing.T) string {
	t.Helper()
	// backend/internal/agui -> backend/internal -> backend -> repo root
	p := filepath.Join("..", "..", "..",
		"agents", "shared", "tests", "contract", "0091_lineage_wire.json")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("shared 0091 wire contract not found at %s: %v\n"+
			"This file is the cross-language pin between the Go parser and the "+
			"Python agent; if it moved, update BOTH suites that read it.", p, err)
	}
	return p
}

type wireContract struct {
	RequestKey string          `json:"request_key"`
	Request    json.RawMessage `json:"request"`
	Result     json.RawMessage `json:"result"`
	Outcomes   []string        `json:"outcomes"`
	Closing    string          `json:"closing_outcome"`
}

func loadWireContract(t *testing.T) wireContract {
	t.Helper()
	raw, err := os.ReadFile(wireContractPath(t))
	if err != nil {
		t.Fatalf("read wire contract: %v", err)
	}
	var c wireContract
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse wire contract: %v", err)
	}
	return c
}

// jsonKeys returns the sorted top-level key names of a JSON object.
func jsonKeys(t *testing.T, raw []byte) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal object: %v", err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// marshalKeys returns the sorted key names Go actually emits for v.
func marshalKeys(t *testing.T, v any) []string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return jsonKeys(t, raw)
}

// TestGoRequestKeysMatchTheSharedContract pins the keys the backend SENDS.
//
// A fully-populated LineageCheckRequest must marshal to exactly the key set
// the contract declares — no more (a key the agent does not read is dead
// weight it will ignore) and no fewer (a key the agent reads and never
// receives is an `unconfirmable` on every scan).
func TestGoRequestKeysMatchTheSharedContract(t *testing.T) {
	c := loadWireContract(t)

	if c.RequestKey != "lineage_checks_requested" {
		t.Fatalf("contract request_key = %q, want lineage_checks_requested "+
			"(this is the top-level key agent_proxy_service.go sets)", c.RequestKey)
	}

	// The envelope: {schema, rows}.
	want := jsonKeys(t, c.Request)
	got := marshalKeys(t, model.LineageChecksRequest{
		Schema: model.LineageChecksRequestSchema,
		Rows:   []model.LineageCheckRequest{{LineageID: "x"}},
	})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LineageChecksRequest emits keys %v, contract declares %v", got, want)
	}

	// One row: every field populated so `omitempty` cannot hide a rename.
	var contractReq struct {
		Schema int               `json:"schema"`
		Rows   []json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(c.Request, &contractReq); err != nil {
		t.Fatalf("parse contract request: %v", err)
	}
	if contractReq.Schema != model.LineageChecksRequestSchema {
		t.Fatalf("contract request schema = %d, Go sends %d",
			contractReq.Schema, model.LineageChecksRequestSchema)
	}
	if len(contractReq.Rows) != 1 {
		t.Fatalf("contract request must carry exactly one fully-populated row, got %d",
			len(contractReq.Rows))
	}
	wantRow := jsonKeys(t, contractReq.Rows[0])
	gotRow := marshalKeys(t, model.LineageCheckRequest{
		LineageID:     "id",
		FingerprintV2: "fp2",
		RelPath:       "a/b.py",
		LineStart:     1,
		LineEnd:       2,
		QuoteHash:     "sha256:x",
		Status:        "open",
		FileHash:      "sha256:y",
	})
	if !reflect.DeepEqual(gotRow, wantRow) {
		t.Fatalf("LineageCheckRequest emits row keys %v, contract declares %v", gotRow, wantRow)
	}
}

// TestGoParsesEveryResultKeyInTheSharedContract pins the keys the backend READS.
//
// Every 0091 field is asserted NON-ZERO. That matters more than it looks: the
// whole family is optional with `omitempty`, so a renamed key parses fine and
// yields a zero value. Only checking that the parsed value carries the
// contract's data can tell "read it" from "silently read nothing".
func TestGoParsesEveryResultKeyInTheSharedContract(t *testing.T) {
	c := loadWireContract(t)

	out := ParseScanOutcome(json.RawMessage(c.Result))
	if out == nil {
		t.Fatal("ParseScanOutcome returned nil for the contract result payload")
	}

	if out.ResultSchema != model.ScanResultSchemaEvidence {
		t.Fatalf("result_schema parsed as %d, want %d — the S26 gate reads this key, "+
			"and a rename makes every scan look like an old agent",
			out.ResultSchema, model.ScanResultSchemaEvidence)
	}
	if !out.HasEvidenceProtocol() {
		t.Fatal("HasEvidenceProtocol() false for a schema-2 contract payload")
	}
	if len(out.PrunedDirs) == 0 {
		t.Fatal("pruned_dirs parsed empty — a rename here reads as " +
			"'nothing was pruned' and closes rows under a directory never walked")
	}
	if !out.ScanTruncated {
		t.Fatal("scan_truncated parsed false for a payload that sets it true")
	}
	if out.DegradedReason == "" {
		t.Fatal("degraded_reason parsed empty — a rename here licenses LLM-tier " +
			"closures on a run that lost its LLM phase (S19)")
	}
	if len(out.LineageChecks) != 1 {
		t.Fatalf("lineage_checks parsed %d rows, want 1 — a rename here reads as "+
			"'the agent answered nothing' and degrades every asked row (§6.4)",
			len(out.LineageChecks))
	}

	// Every field of the check row, so no single key can be renamed unseen.
	chk := out.LineageChecks[0]
	if chk.LineageID == "" {
		t.Fatal("lineage_id parsed empty; indexChecks drops a row with no id")
	}
	if chk.Outcome != model.LineageOutcomeConfirmed {
		t.Fatalf("outcome parsed %q, want %q", chk.Outcome, model.LineageOutcomeConfirmed)
	}
	if chk.Reason == "" {
		t.Fatal("reason parsed empty")
	}
	if chk.LineStart == 0 || chk.LineEnd == 0 {
		t.Fatalf("line window parsed (%d,%d); both must survive", chk.LineStart, chk.LineEnd)
	}
	if chk.FileHash == "" {
		t.Fatal("file_hash parsed empty; boundedFixedRows compares it across scans")
	}
}

// TestOutcomeVocabularyMatchesTheSharedContract pins the five outcome STRINGS.
//
// These are compared with `==` in applyCheck and the default branch is
// `unconfirmable`. So a one-character disagreement between the two languages
// does not error — it routes `confirmed` into the default and marks a live,
// still-present finding `unconfirmed` forever. Order is significant here only
// as documentation; the sets are what is asserted.
func TestOutcomeVocabularyMatchesTheSharedContract(t *testing.T) {
	c := loadWireContract(t)

	goOutcomes := []string{
		model.LineageOutcomeConfirmed,
		model.LineageOutcomeReanchored,
		model.LineageOutcomeAmbiguous,
		model.LineageOutcomeGone,
		model.LineageOutcomeUnconfirmable,
	}
	if !reflect.DeepEqual(goOutcomes, c.Outcomes) {
		t.Fatalf("Go outcome constants %v, contract declares %v", goOutcomes, c.Outcomes)
	}
	if c.Closing != model.LineageOutcomeGone {
		t.Fatalf("contract closing_outcome = %q, Go closes on %q — only ONE outcome "+
			"may close a row, and it must be a fact about the code",
			c.Closing, model.LineageOutcomeGone)
	}
}

// TestFindingQuoteHashCrossesTheSnapshotBoundary pins `quote_hash` on a
// finding, which is a THIRD wire path and the one that bootstraps everything
// else: it is written onto the lineage row at creation
// (`createNewLineage`), and a row without it is never sent for checking
// (`checkableLLMRow`). Renamed, the feature does not fail — it never starts,
// because no row is ever eligible to be asked about.
func TestFindingQuoteHashCrossesTheSnapshotBoundary(t *testing.T) {
	c := loadWireContract(t)

	findings, malformed := ParseSnapshotFindings(json.RawMessage(c.Result), "cwe")
	if malformed != 0 {
		t.Fatalf("contract findings failed to parse: %d malformed", malformed)
	}
	if len(findings) != 1 {
		t.Fatalf("parsed %d findings from the contract payload, want 1", len(findings))
	}
	if findings[0].QuoteHash == "" {
		t.Fatal("Finding.QuoteHash parsed empty — with no quote hash, " +
			"checkableLLMRow rejects the row and it is never checked at all")
	}
	if findings[0].Provenance == "" {
		t.Fatal("Finding.Provenance parsed empty — TierOf() would classify the " +
			"row deterministic and close it on the model's silence")
	}
	if model.TierOf(findings[0].Provenance) != model.TierLLM {
		t.Fatalf("TierOf(%q) = %q, want %q",
			findings[0].Provenance, model.TierOf(findings[0].Provenance), model.TierLLM)
	}
}
