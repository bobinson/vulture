package repository

// Feature 0102 (§10.1, A42 (3)) — the AST tier's evidence survives ingest and
// persistence whole.
//
// An AST-owned row carries its evidence as two top-level keys of its existing
// validation blob, `ast` and `flow`, written by the agent. Like 0074's
// provenance_origins they are never checks[] entries, and Go has no field for
// either: the backend carries the blob whole. DecodeAgentFinding (every ingest
// path: result snapshot, read-only delta tap, persisted delta) decodes it into
// model.Finding.Validation, a map, so keys Go does not know survive, and both
// repos marshal that map into the one validation column. This pins the chain
// on one row: the agent's `result` snapshot, parsed as the stream handler
// parses it, saved and read back through GetAudit, keeps the agent's blob
// unchanged. The Postgres twin is ast_validation_persist_0102_integration_test.go.

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/vulture/backend/internal/agui"
	"github.com/vulture/backend/internal/model"
)

// astResult0102 is an agent `result` snapshot holding one AST-owned row, its
// validation blob as the agent's validate stage leaves it: the stage's keys,
// then the tier's `ast` and `flow` (§10.1).
const astResult0102 = `{"findings": [{
	"id": "f-ast-1", "severity": "high", "check_id": "cwe.input_validation.path_traversal",
	"category": "CWE-22", "title": "Path traversal", "file_path": "src/app.ts",
	"line_start": 19, "line_end": 19, "provenance": "skill",
	"validation_status": "high_confidence", "validation_confidence": 0.9,
	"validation": {
		"status": "high_confidence", "confidence": 0.9,
		"checks": [{"id": "obligation", "result": "discharged", "weight": 0.1, "reason": "", "extras": {}}],
		"validated_at": "2026-10-19T12:00:00.000000Z",
		"ast": {"engine": "ast", "grammar": "tree_sitter_typescript.language_typescript@0.23.2", "model_schema": 2},
		"flow": {"family": "path", "origins": ["external:request"], "via": [], "guards": ["validate"],
			"hops": [{"line": 12, "kind": "param", "name": "req"}, {"line": 14, "kind": "assign", "name": "p"},
				{"line": 19, "kind": "sink", "name": "fs.readFile"}],
			"truncated": false}}}]}`

// findingRoundTripper is the slice of both repositories the round trip needs.
type findingRoundTripper interface {
	auditSeeder
	SaveFindings(string, []model.Finding) error
	GetAudit(string) (*model.Audit, error)
}

// sentValidation0102 is the agent's validation blob of astResult0102, as JSON decodes it.
func sentValidation0102(t *testing.T) map[string]interface{} {
	t.Helper()
	var envelope struct {
		Findings []struct {
			Validation map[string]interface{} `json:"validation"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(astResult0102), &envelope); err != nil {
		t.Fatalf("unmarshal the fixture: %v", err)
	}
	return envelope.Findings[0].Validation
}

// parsedASTRow is the one row of astResult0102, ingested as the stream handler
// ingests a result snapshot, for audit auditID.
func parsedASTRow(t *testing.T, auditID string) model.Finding {
	t.Helper()
	rows, malformed := agui.ParseSnapshotFindings(json.RawMessage(astResult0102), "cwe")
	if malformed != 0 || len(rows) != 1 {
		t.Fatalf("parse: %d row(s), %d malformed; want 1 and 0", len(rows), malformed)
	}
	rows[0].AuditID = auditID
	return rows[0]
}

// readBackOne is the one finding of auditID, read through GetAudit (the API
// and replay read path).
func readBackOne(t *testing.T, repo findingRoundTripper, auditID string) model.Finding {
	t.Helper()
	a, err := repo.GetAudit(auditID)
	if err != nil || a == nil || len(a.Findings) != 1 {
		t.Fatalf("get audit: %v — want exactly one row back; nothing else here proves anything", err)
	}
	return a.Findings[0]
}

// roundTripASTValidation saves the parsed row on repo and requires its whole
// validation blob back, `ast` and `flow` included.
func roundTripASTValidation(t *testing.T, repo findingRoundTripper) {
	t.Helper()
	auditID := seedAuditOn(t, repo)
	if err := repo.SaveFindings(auditID, []model.Finding{parsedASTRow(t, auditID)}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got, want := readBackOne(t, repo, auditID).Validation, sentValidation0102(t); !reflect.DeepEqual(got, want) {
		t.Errorf("the validation blob did not survive whole:\n got %v\nwant %v", got, want)
	}
}

// §10.1 / A42 (3): result snapshot -> SQLite -> GetAudit keeps validation.ast and validation.flow.
func TestSQLiteValidationAstAndFlowSurviveIngestAndPersistence_0102(t *testing.T) {
	roundTripASTValidation(t, newTestSQLite(t))
}
