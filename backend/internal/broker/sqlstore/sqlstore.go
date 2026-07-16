// Package sqlstore provides the SQL implementations of the broker's
// emergency-kill store seams (feature 0064, §6/§25.2, §29): the kid Denylist,
// the per-run jti Revocation store, and the metering AuditLog, over the
// kid_denylist / revoked_jti / llm_audit_log tables. It is dialect-parameterized
// (Postgres AND SQLite) via dialect.Kind — one query set, authored with `?` and
// rebound per driver. Each kill read goes through a small TTL-bounded in-memory
// cache so the per-verify / per-turn hot path does not hit the DB every call,
// while an emergency revocation still propagates within the cache TTL (≤ a few
// seconds, §6). A backing-store failure with no fresh cached answer surfaces
// token.ErrRevocationUnavailable so the caller fails CLOSED.
package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/vulture/backend/internal/broker/budget"
	"github.com/vulture/backend/internal/broker/dialect"
	"github.com/vulture/backend/internal/broker/token"
)

// DefaultCacheTTL bounds how stale a cached denylist/revocation answer may be
// — i.e. the worst-case propagation delay of an emergency kill (§6).
const DefaultCacheTTL = 2 * time.Second

// maxCacheEntries caps the cache so a flood of distinct kids/jtis cannot grow
// it without bound; on overflow the cache is cleared (correctness is preserved
// — a miss just re-queries Postgres).
const maxCacheEntries = 10000

// flagCache is a bounded, TTL'd cache in front of a boolean backing-store probe.
// It is the sole place the fail-closed policy lives, so it is unit-testable with
// an injected probe (no DB needed).
type flagCache struct {
	ttl   time.Duration
	max   int
	now   func() time.Time
	probe func(key string) (bool, error)

	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	val bool
	exp time.Time
}

func newFlagCache(ttl time.Duration, max int, now func() time.Time, probe func(string) (bool, error)) *flagCache {
	if now == nil {
		now = time.Now
	}
	return &flagCache{ttl: ttl, max: max, now: now, probe: probe, entries: map[string]cacheEntry{}}
}

// get returns the cached value if fresh, otherwise probes the backing store and
// caches the result. A probe error is returned verbatim (the caller wraps it as
// fail-closed) and is NOT cached.
func (c *flagCache) get(key string) (bool, error) {
	if v, ok := c.fresh(key); ok {
		return v, nil
	}
	val, err := c.probe(key)
	if err != nil {
		return false, err
	}
	c.store(key, val)
	return val, nil
}

func (c *flagCache) fresh(key string) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || c.now().After(e.exp) {
		return false, false
	}
	return e.val, true
}

func (c *flagCache) store(key string, val bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		c.entries = map[string]cacheEntry{} // simple bounded eviction
	}
	c.entries[key] = cacheEntry{val: val, exp: c.now().Add(c.ttl)}
}

// invalidate drops a key so a just-written revocation is visible immediately to
// this replica (other replicas converge within the TTL).
func (c *flagCache) invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Denylist is the Postgres-backed kid denylist (token.Denylist).
type Denylist struct {
	db  *sql.DB
	dia dialect.Kind
	c   *flagCache
}

// NewDenylist builds the kid denylist over kid_denylist with the given cache TTL
// (use DefaultCacheTTL). It queries within ctx-less short timeouts per call.
func NewDenylist(db *sql.DB, dia dialect.Kind, ttl time.Duration) *Denylist {
	d := &Denylist{db: db, dia: dia}
	d.c = newFlagCache(ttl, maxCacheEntries, nil, d.query)
	return d
}

func (d *Denylist) query(kid string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var exists bool
	err := d.db.QueryRowContext(ctx, d.dia.Rebind(
		`SELECT EXISTS(SELECT 1 FROM kid_denylist WHERE kid = ?)`), kid).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// IsDenied reports whether kid is denied; a store failure fails CLOSED.
func (d *Denylist) IsDenied(kid string) (bool, error) {
	denied, err := d.c.get(kid)
	if err != nil {
		return false, fmt.Errorf("%w: denylist query", token.ErrRevocationUnavailable)
	}
	return denied, nil
}

// Deny adds kid to the denylist (emergency revocation) and invalidates the
// local cache so this replica rejects it immediately.
func (d *Denylist) Deny(kid string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := d.db.ExecContext(ctx, d.dia.Rebind(
		`INSERT INTO kid_denylist (kid) VALUES (?) ON CONFLICT (kid) DO NOTHING`), kid); err != nil {
		return fmt.Errorf("deny kid: %w", err)
	}
	d.c.invalidate(kid)
	return nil
}

// Revocation is the Postgres-backed per-run jti revocation store
// (token.Revocation).
type Revocation struct {
	db  *sql.DB
	dia dialect.Kind
	ttl time.Duration
	c   *flagCache
}

// NewRevocation builds the jti revocation store over revoked_jti.
func NewRevocation(db *sql.DB, dia dialect.Kind, ttl time.Duration) *Revocation {
	r := &Revocation{db: db, dia: dia, ttl: ttl}
	r.c = newFlagCache(ttl, maxCacheEntries, nil, r.query)
	return r
}

func (r *Revocation) query(jti string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var exists bool
	err := r.db.QueryRowContext(ctx, r.dia.Rebind(
		`SELECT EXISTS(SELECT 1 FROM revoked_jti WHERE jti = ?)`), jti).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// IsRevoked reports whether jti is revoked; a store failure fails CLOSED.
func (r *Revocation) IsRevoked(jti string) (bool, error) {
	revoked, err := r.c.get(jti)
	if err != nil {
		return false, fmt.Errorf("%w: revocation query", token.ErrRevocationUnavailable)
	}
	return revoked, nil
}

// Revoke marks jti revoked (run end/cancel), stamping an expiry a janitor can
// prune past max token lifetime, and invalidates the local cache.
func (r *Revocation) Revoke(jti string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := r.db.ExecContext(ctx, r.dia.Rebind(
		`INSERT INTO revoked_jti (jti, expires_at) VALUES (?, ?)
		 ON CONFLICT (jti) DO NOTHING`), jti, time.Now().Add(24*time.Hour)); err != nil {
		return fmt.Errorf("revoke jti: %w", err)
	}
	r.c.invalidate(jti)
	return nil
}

// Compile-time assertions the PG stores satisfy the broker seams.
var (
	_ token.Denylist   = (*Denylist)(nil)
	_ token.Revocation = (*Revocation)(nil)
)

// AuditLog is the Postgres-backed §14 metering writer: one llm_audit_log row
// per completion. It never records prompt/completion content (N6) and is
// best-effort — a write failure is logged, not surfaced (the completion
// already succeeded).
type AuditLog struct {
	db  *sql.DB
	dia dialect.Kind
}

// NewAuditLog builds the metering-log writer over llm_audit_log.
func NewAuditLog(db *sql.DB, dia dialect.Kind) *AuditLog { return &AuditLog{db: db, dia: dia} }

// Log records one completion's metering row (§14 P0 slice).
func (a *AuditLog) Log(ctx context.Context, e budget.LedgerEntry, cached bool) {
	if _, err := a.db.ExecContext(ctx, a.dia.Rebind(
		`INSERT INTO llm_audit_log
		    (run_id, request_id, tenant_id, provider, model,
		     input_tokens, output_tokens, cost_usd, cache_hit, estimated)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`),
		e.RunID, e.RequestID, e.TenantID, e.Provider, e.Model,
		e.InputTokens, e.OutputTokens, e.CostUSD, cached, e.Estimated,
	); err != nil {
		log.Printf("broker: audit-log write failed run=%s request=%s: %v", e.RunID, e.RequestID, err)
	}
}
