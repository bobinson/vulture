//go:build integration

package repository

// Feature 0102 (§10.1, A42 (3)) — Postgres half of the validation.ast /
// validation.flow round trip. Same fixture, ingest and assertion as the SQLite
// test (ast_validation_persist_0102_test.go). SKIPs when POSTGRES_TEST_DSN is
// unset (via newPGProvenanceRepo).

import "testing"

func TestPGValidationAstAndFlowSurviveIngestAndPersistence_0102(t *testing.T) {
	roundTripASTValidation(t, newPGProvenanceRepo(t))
}
