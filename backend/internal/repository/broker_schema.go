package repository

import (
	"database/sql"
	"fmt"
)

// MigrateBrokerTables creates the LLM-broker tables on SQLite (feature 0064
// §29). It is the SQLite counterpart of the Postgres migration 024: same
// tables + keys + indexes, SQLite-native types — money as REAL (a documented
// single-process precision tradeoff vs Postgres NUMERIC(18,8)), booleans as
// INTEGER 0/1, and the audit-log id as INTEGER PRIMARY KEY AUTOINCREMENT
// (vs BIGSERIAL). Every statement is IF NOT EXISTS (idempotent), matching the
// migration-authoring contract. Exported so the broker conformance suite can
// build a hermetic SQLite store from the same source of truth.
func MigrateBrokerTables(db *sql.DB) error {
	stmts := []string{
		// Append-only cost ledger. PK (run_id,request_id) makes reconcile
		// INSERTs replay-safe via ON CONFLICT DO NOTHING.
		`CREATE TABLE IF NOT EXISTS llm_ledger (
			run_id        TEXT NOT NULL,
			request_id    TEXT NOT NULL,
			tenant_id     TEXT NOT NULL DEFAULT 'local',
			model         TEXT NOT NULL,
			provider      TEXT NOT NULL,
			input_tokens  INTEGER NOT NULL DEFAULT 0,
			output_tokens INTEGER NOT NULL DEFAULT 0,
			cost_usd      REAL NOT NULL DEFAULT 0,
			estimated     INTEGER NOT NULL DEFAULT 0,
			created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (run_id, request_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_llm_ledger_tenant ON llm_ledger (tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_llm_ledger_created ON llm_ledger (created_at DESC)`,

		// Leased reservations. PK mirrors the ledger so the sweeper reclaims
		// only leases with NO matching ledger row.
		`CREATE TABLE IF NOT EXISTS llm_lease (
			run_id         TEXT NOT NULL,
			request_id     TEXT NOT NULL,
			tenant_id      TEXT NOT NULL DEFAULT 'local',
			shard          INTEGER NOT NULL DEFAULT 0,
			reserved       REAL NOT NULL DEFAULT 0,
			model_snapshot TEXT NOT NULL,
			expires_at     TIMESTAMP NOT NULL,
			created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (run_id, request_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_llm_lease_expires ON llm_lease (expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_llm_lease_tenant_shard ON llm_lease (tenant_id, shard)`,

		// Sharded per-tenant budget counters. Reserve is a CAS UPDATE against a
		// shard where reserved + spent + :est <= cap.
		`CREATE TABLE IF NOT EXISTS llm_budget_shard (
			tenant_id  TEXT NOT NULL DEFAULT 'local',
			shard      INTEGER NOT NULL DEFAULT 0,
			reserved   REAL NOT NULL DEFAULT 0,
			spent      REAL NOT NULL DEFAULT 0,
			cap        REAL NOT NULL DEFAULT 0,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, shard)
		)`,

		// Revoked per-run token ids (jti).
		`CREATE TABLE IF NOT EXISTS revoked_jti (
			jti        TEXT PRIMARY KEY,
			tenant_id  TEXT NOT NULL DEFAULT 'local',
			revoked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_revoked_jti_expires ON revoked_jti (expires_at)`,

		// Emergency mint-key kill switch (kid).
		`CREATE TABLE IF NOT EXISTS kid_denylist (
			kid       TEXT PRIMARY KEY,
			reason    TEXT,
			denied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		// Metering audit log: one row per completion. Content is NEVER stored.
		`CREATE TABLE IF NOT EXISTS llm_audit_log (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id        TEXT NOT NULL,
			request_id    TEXT NOT NULL,
			tenant_id     TEXT NOT NULL DEFAULT 'local',
			provider      TEXT NOT NULL,
			model         TEXT NOT NULL,
			input_tokens  INTEGER NOT NULL DEFAULT 0,
			output_tokens INTEGER NOT NULL DEFAULT 0,
			cost_usd      REAL NOT NULL DEFAULT 0,
			cache_hit     INTEGER NOT NULL DEFAULT 0,
			estimated     INTEGER NOT NULL DEFAULT 0,
			created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_llm_audit_log_run ON llm_audit_log (run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_llm_audit_log_tenant ON llm_audit_log (tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_llm_audit_log_created ON llm_audit_log (created_at DESC)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("broker schema: %w", err)
		}
	}
	return nil
}
