-- Feature 0064: LLM Broker (P0, Postgres-only) — schema only, no runtime wiring.
--
-- These tables back the key-isolation + cost-governance gateway (see
-- docs/features/0064_llm_broker/0064_llm_broker_lld.md §15). Vulture has no
-- first-class `tenant` entity yet (LLD §21); P0 keys everything by a TEXT
-- tenant_id whose Mode-A default is 'local'. TEXT (not a UUID FK) is used
-- deliberately so these tables carry no FK to existing UUID-keyed tables
-- and stay self-contained — avoiding the FK type-mismatch class of bug the
-- migration_authoring guide warns about.
--
-- Every statement is idempotent (CREATE ... IF NOT EXISTS) per the guide.

-- Append-only cost ledger. PK (run_id, request_id) makes reconcile
-- INSERTs replay-safe via ON CONFLICT DO NOTHING (LLD §8, M1).
CREATE TABLE IF NOT EXISTS llm_ledger (
    run_id        TEXT NOT NULL,
    request_id    TEXT NOT NULL,
    tenant_id     TEXT NOT NULL DEFAULT 'local',
    model         TEXT NOT NULL,
    provider      TEXT NOT NULL,
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd      NUMERIC(18, 8) NOT NULL DEFAULT 0,
    estimated     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, request_id)
);
CREATE INDEX IF NOT EXISTS idx_llm_ledger_tenant ON llm_ledger (tenant_id);
CREATE INDEX IF NOT EXISTS idx_llm_ledger_created ON llm_ledger (created_at DESC);

-- Leased reservations. PK (run_id, request_id) mirrors the ledger so the
-- sweeper can reclaim only leases with NO matching ledger row (LLD §8, M1).
CREATE TABLE IF NOT EXISTS llm_lease (
    run_id         TEXT NOT NULL,
    request_id     TEXT NOT NULL,
    tenant_id      TEXT NOT NULL DEFAULT 'local',
    shard          INTEGER NOT NULL DEFAULT 0,
    reserved       NUMERIC(18, 8) NOT NULL DEFAULT 0,
    model_snapshot TEXT NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, request_id)
);
CREATE INDEX IF NOT EXISTS idx_llm_lease_expires ON llm_lease (expires_at);
CREATE INDEX IF NOT EXISTS idx_llm_lease_tenant_shard ON llm_lease (tenant_id, shard);

-- Sharded per-tenant budget counters. N sub-rows per (tenant_id, shard)
-- remove the single-row serialization point (LLD §8/§13, H1). Reserve is a
-- CAS UPDATE against a random shard where reserved + spent + :est <= cap.
CREATE TABLE IF NOT EXISTS llm_budget_shard (
    tenant_id  TEXT NOT NULL DEFAULT 'local',
    shard      INTEGER NOT NULL DEFAULT 0,
    reserved   NUMERIC(18, 8) NOT NULL DEFAULT 0,
    spent      NUMERIC(18, 8) NOT NULL DEFAULT 0,
    cap        NUMERIC(18, 8) NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, shard)
);

-- Revoked per-run token ids (jti). Checked at every turn boundary; a run
-- ending/cancelling inserts its jti here (LLD §6/§12, M3).
CREATE TABLE IF NOT EXISTS revoked_jti (
    jti        TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL DEFAULT 'local',
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- expires_at lets a janitor prune entries once past max token lifetime.
    expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_revoked_jti_expires ON revoked_jti (expires_at);

-- Emergency mint-key kill switch. A compromised signing-key id (kid) is
-- added here and checked on every verify (LLD §6/§16, H3).
CREATE TABLE IF NOT EXISTS kid_denylist (
    kid        TEXT PRIMARY KEY,
    reason     TEXT,
    denied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-tenant BYO provider keys + endpoint (LLD §7/§11/§15). base_url is
-- UNTRUSTED and SSRF-validated on every use. key_enc is envelope-encrypted
-- ciphertext — plaintext keys are NEVER stored or logged (N6).
CREATE TABLE IF NOT EXISTS tenant_provider_keys (
    tenant_id  TEXT NOT NULL DEFAULT 'local',
    provider   TEXT NOT NULL,
    key_enc    BYTEA NOT NULL,
    base_url   TEXT,
    region     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, provider)
);

-- Metering audit log: one row per completion (LLD §11/§14/§15). Content is
-- secret-class and NEVER stored here — only run/tenant/model/tokens/cost/
-- cache-hit metadata for the metering source.
CREATE TABLE IF NOT EXISTS llm_audit_log (
    id            BIGSERIAL PRIMARY KEY,
    run_id        TEXT NOT NULL,
    request_id    TEXT NOT NULL,
    tenant_id     TEXT NOT NULL DEFAULT 'local',
    provider      TEXT NOT NULL,
    model         TEXT NOT NULL,
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd      NUMERIC(18, 8) NOT NULL DEFAULT 0,
    cache_hit     BOOLEAN NOT NULL DEFAULT FALSE,
    estimated     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_llm_audit_log_run ON llm_audit_log (run_id);
CREATE INDEX IF NOT EXISTS idx_llm_audit_log_tenant ON llm_audit_log (tenant_id);
CREATE INDEX IF NOT EXISTS idx_llm_audit_log_created ON llm_audit_log (created_at DESC);
