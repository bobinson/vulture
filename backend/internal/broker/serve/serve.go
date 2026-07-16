// Package serve is the LLM-broker composition root (feature 0064, §25.2): it
// assembles the fully-wired broker HTTP handler + a per-run token mint/revoke
// facility from a BrokerConfig and a SQL store handle (Postgres OR SQLite, §29),
// and runs the lease sweeper. The backend mounts Handler() on an internal-only
// listener and calls MintForAgent at audit dispatch / RevokeRun at run end.
package serve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/vulture/backend/internal/broker/budget"
	"github.com/vulture/backend/internal/broker/dialect"
	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/modelmeta"
	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/resilience"
	"github.com/vulture/backend/internal/broker/server"
	"github.com/vulture/backend/internal/broker/sqlstore"
	"github.com/vulture/backend/internal/broker/token"
	"github.com/vulture/backend/internal/config"
)

// brokerKID is the fixed signing-key id for the P0 in-process deployment, where
// the same process mints and verifies. Multi-process/rotation (distinct kids,
// JWKS distribution) is P1.
const brokerKID = "vulture-broker-p0"

// sweepInterval is how often the lease sweeper reclaims expired, un-reconciled
// leases (§8/§26 M12).
const sweepInterval = 30 * time.Second

// Broker is the assembled, ready-to-serve LLM broker plus its per-run token
// mint/revoke facility. It is nil-safe: a disabled build returns a Broker whose
// Enabled is false and whose Mint/Revoke are no-ops.
type Broker struct {
	Enabled bool
	Handler http.Handler

	minter     token.Minter
	revocation token.Revocation
	region     string
	ttl        time.Duration
	models     []string       // primary + fallbacks — the scope covers task:model for each
	verify     token.Verifier // used to read back a freshly-minted jti for revocation tracking

	mu      sync.Mutex
	runJTIs map[string][]string // run_id → minted jtis (for RevokeRun)

	stopSweep context.CancelFunc
}

// Build assembles the broker from its config, the resolved primary model, a SQL
// store handle, and its dialect (Postgres OR SQLite, §29). The caller MUST gate
// on cfg.Enabled && db != nil (the broker requires a store). A returned Broker
// with Enabled=false means the config was present but unusable; callers treat it
// as "broker off".
func Build(cfg config.BrokerConfig, primaryModel string, db *sql.DB, dia dialect.Kind) (*Broker, error) {
	privPEM, pubPEM, err := resolveKeypair(cfg.MintKey)
	if err != nil {
		return nil, fmt.Errorf("broker keypair: %w", err)
	}
	minter, err := token.NewMinter(privPEM, brokerKID)
	if err != nil {
		return nil, fmt.Errorf("broker minter: %w", err)
	}
	denylist := sqlstore.NewDenylist(db, dia, sqlstore.DefaultCacheTTL)
	revocation := sqlstore.NewRevocation(db, dia, sqlstore.DefaultCacheTTL)
	verifier, err := token.NewVerifier(map[string][]byte{brokerKID: pubPEM}, denylist, revocation)
	if err != nil {
		return nil, fmt.Errorf("broker verifier: %w", err)
	}

	// Resolve the default egress route: an operator can point the broker at a
	// local OpenAI-compatible server (LM Studio / Ollama / vLLM) for self-host.
	defaultProvider := cfg.Provider
	if defaultProvider == "" {
		defaultProvider = "openai"
	}
	allowlist := egress.NewAllowlist(allowlistOrDefault(cfg.ProviderAllowlist, defaultProvider)...)
	ssrf := egress.NewSSRFValidator(allowlist, netResolver)
	if cfg.AllowLocalEgress {
		// Dev/self-host: permit loopback/RFC1918 + http for the configured local
		// provider (link-local/IMDS/multicast stay blocked, §11).
		ssrf = egress.NewSSRFValidatorAllowingLocal(allowlist, netResolver)
	}

	budgetDB := budget.NewSQLDB(db, dia)
	// Provision the tenant budget: the sharded CAS reserves against existing
	// llm_budget_shard rows, so without seeded rows EVERY request fails closed
	// (budget_exceeded). Seed tenant "local" (§21) with cap = BudgetUSD split
	// across shards, or an effectively-unlimited cap when no cap is set
	// (VULTURE_LLM_BUDGET_USD <= 0 ⇒ "no cap", §17). ON CONFLICT preserves an
	// existing tenant's cap + accumulated spend across restarts.
	if err := seedTenantBudget(db, dia, "local", cfg.BudgetShards, cfg.BudgetUSD); err != nil {
		return nil, fmt.Errorf("seed budget: %w", err)
	}
	deps := server.Dependencies{
		Verifier:        verifier,
		Denylist:        denylist,
		Revocation:      revocation,
		Budget:          budget.NewManager(budgetDB, cfg.BudgetShards),
		Selector:        egress.NewConfigSelector(primaryModel, cfg.Fallbacks),
		SSRF:            ssrf,
		Allowlist:       allowlist,
		Adapters:        defaultAdapters(cfg.CallTimeoutSec, defaultProvider),
		Keys:            keysFromEnv(defaultProvider),
		DefaultProvider: defaultProvider,
		// §30: egress SSRF-validates + pins a CONCRETE base URL before the
		// adapter runs, so a native cloud provider needs its canonical endpoint
		// when no explicit base URL is configured (gemini/anthropic would
		// otherwise hit egress with an empty URL and fail). An operator override
		// (VULTURE_LLM_BROKER_PROVIDER_BASE_URL, e.g. a local LM Studio) wins.
		DefaultBaseURL: defaultBaseURL(cfg.ProviderBaseURL, defaultProvider),
		Breakers:       resilience.NewBreakerPool(resilience.CircuitConfig{FailureThreshold: 5, OpenTimeout: 30 * time.Second, HalfOpenMaxCalls: 1, SuccessThreshold: 1, IsFailure: breakerCountsAsFailure}),
		Bulkheads:      resilience.NewBulkheadPool(resilience.BulkheadConfig{MaxConcurrent: 16}),
		Retriers:       resilience.NewRetrierPool(retrierConfig()),
		CallTimeoutSec: cfg.CallTimeoutSec,
		AuditLog:       sqlstore.NewAuditLog(db, dia),
		DBHealth:       db.PingContext,
	}

	b := &Broker{
		Enabled:    true,
		Handler:    server.New(deps).Handler(),
		minter:     minter,
		revocation: revocation,
		region:     "local",
		ttl:        24 * time.Hour,
		models:     append([]string{primaryModel}, cfg.Fallbacks...),
		verify:     verifier,
		runJTIs:    map[string][]string{},
	}
	b.startSweeper(budgetDB)
	return b, nil
}

// Disabled returns an inert broker (Enabled=false) whose Mint/Revoke are
// no-ops — used when the config is off or no store is available so callers
// need no nil checks.
func Disabled() *Broker { return &Broker{Enabled: false} }

// MintForAgent mints a per-run token for the dispatched agent, scoped to
// taskType across every model the selector may resolve (primary + fallbacks),
// so a mid-run failover to a fallback model stays in scope (§7). It records the
// jti so RevokeRun can revoke it at run end. Returns "" (no token) when the
// broker is disabled — Mode A behavior.
func (b *Broker) MintForAgent(runID, taskType string) (string, error) {
	if b == nil || !b.Enabled {
		return "", nil
	}
	scope := make([]string, 0, len(b.models))
	for _, m := range b.models {
		if m != "" {
			scope = append(scope, taskType+":"+m)
		}
	}
	tok, err := b.minter.Mint(token.MintRequest{
		RunID:      runID,
		TenantID:   "local",
		Scope:      scope,
		BudgetRef:  "local",
		Region:     b.region,
		TTLSeconds: int64(b.ttl / time.Second),
	})
	if err != nil {
		return "", fmt.Errorf("mint broker token: %w", err)
	}
	if claims, verr := b.verify.Verify(tok); verr == nil {
		b.track(runID, claims.JTI)
	}
	return tok, nil
}

// ContextWindow resolves the run's primary model's context window (tokens) via
// the broker-owned registry (§31), honoring a VULTURE_LLM_CTX_SIZE override. It
// is injected at dispatch so the agent sizes its LLM phase without its own
// table. Returns 0 when disabled / no model — the caller then injects nothing
// and the agent falls back to its own resolution (Mode A unchanged).
func (b *Broker) ContextWindow() int {
	if b == nil || !b.Enabled || len(b.models) == 0 {
		return 0
	}
	return modelmeta.ResolveContextWindow(b.models[0], os.Getenv("VULTURE_LLM_CTX_SIZE"))
}

// RevokeRun revokes every token minted for runID (§6/M3, run end/cancel).
// Best-effort: a revocation-store error is logged, not surfaced (tokens are
// short-TTL, so revocation is defense-in-depth). No-op when disabled.
func (b *Broker) RevokeRun(runID string) {
	if b == nil || !b.Enabled {
		return
	}
	b.mu.Lock()
	jtis := b.runJTIs[runID]
	delete(b.runJTIs, runID)
	b.mu.Unlock()
	for _, jti := range jtis {
		if err := b.revocation.Revoke(jti); err != nil {
			log.Printf("broker: revoke jti for run %s failed: %v", runID, err)
		}
	}
}

// Close stops the lease sweeper.
func (b *Broker) Close() {
	if b != nil && b.stopSweep != nil {
		b.stopSweep()
	}
}

func (b *Broker) track(runID, jti string) {
	b.mu.Lock()
	b.runJTIs[runID] = append(b.runJTIs[runID], jti)
	b.mu.Unlock()
}

func (b *Broker) startSweeper(db budget.DB) {
	ctx, cancel := context.WithCancel(context.Background())
	b.stopSweep = cancel
	go func() {
		t := time.NewTicker(sweepInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := db.SweepExpiredLeases(ctx, time.Now()); err != nil {
					log.Printf("broker: lease sweep failed: %v", err)
				}
			}
		}
	}()
}

// --- helpers ---

// resolveKeypair returns the (private, public) PEM pair. If mintKeyPEM is set it
// is parsed and its public key derived; otherwise an EPHEMERAL P-256 keypair is
// generated (dev/single-process convenience — tokens do not survive restart and
// are not shared across replicas; production sets VULTURE_LLM_BROKER_MINT_KEY).
func resolveKeypair(mintKeyPEM string) (priv, pub []byte, err error) {
	var key *ecdsa.PrivateKey
	if mintKeyPEM == "" {
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, nil, err
		}
		log.Printf("broker: no VULTURE_LLM_BROKER_MINT_KEY set — using an ephemeral P-256 key (dev/single-process only)")
		priv = marshalPriv(key)
	} else {
		priv = []byte(mintKeyPEM)
		if key, err = parsePriv(priv); err != nil {
			return nil, nil, err
		}
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pub = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return priv, pub, nil
}

func marshalPriv(key *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func parsePriv(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("mint key is not valid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("mint key is not an EC private key")
	}
	return key, nil
}

// netResolver is the production SSRF resolver (real DNS).
func netResolver(host string) ([]net.IP, error) { return net.LookupIP(host) }

// defaultBaseURL resolves the broker's egress base URL: an explicit operator
// override wins (a local LM Studio / vLLM / proxy); otherwise the provider's
// canonical endpoint (gemini/anthropic/openai) so egress has a concrete URL to
// SSRF-validate + pin (§30). "" for a bare openai-compatible with no override —
// which is an operator error surfaced at first egress, by design.
func defaultBaseURL(override, defaultProvider string) string {
	if override != "" {
		return override
	}
	return provider.CanonicalBaseURL(defaultProvider)
}

// allowlistOrDefault defaults an empty allowlist to the configured default
// provider, so an operator who enables the broker without setting the
// allowlist still gets a working egress rather than a broker that blocks all.
func allowlistOrDefault(list []string, defaultProvider string) []string {
	if len(list) == 0 {
		return []string{defaultProvider}
	}
	return list
}

// defaultAdapters is the P0 adapter set: first-party openai + an
// openai-compatible adapter (LM Studio / vLLM / LiteLLM proxy), keyed by name.
// A non-standard configured default provider gets an OpenAI-compatible adapter
// under its own name so egress can resolve it.
func defaultAdapters(callTimeoutSec int, defaultProvider string) map[string]provider.Adapter {
	timeout := time.Duration(callTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	hc := &http.Client{Timeout: timeout}
	adapters := map[string]provider.Adapter{
		"openai":            provider.NewOpenAIAdapter(hc),
		"openai-compatible": provider.NewOpenAICompatibleAdapter("openai-compatible", hc),
		// §30: native Gemini (generateContent) + Anthropic (Messages) so the
		// broker fronts every provider — the prerequisite for broker-as-default.
		"gemini":    provider.NewGeminiAdapter(hc),
		"anthropic": provider.NewAnthropicAdapter(hc),
	}
	// A non-standard default provider (an unknown local server) gets an
	// OpenAI-compatible adapter under its own name; the native ones above win.
	if _, ok := adapters[defaultProvider]; !ok {
		adapters[defaultProvider] = provider.NewOpenAICompatibleAdapter(defaultProvider, hc)
	}
	return adapters
}

// noCapSentinel is the per-shard cap used when the deployment sets no budget
// cap (VULTURE_LLM_BUDGET_USD <= 0): large enough that reserve never blocks in
// practice, while fitting the llm_budget_shard.cap NUMERIC(18,8) column (integer
// part < 1e10). The ledger still records real spend for metering.
const noCapSentinel = 1e9

// seedTenantBudget inserts the tenant's sharded budget rows (idempotent). With
// capUSD > 0 the cap is split evenly across shards; otherwise each shard gets
// the no-cap sentinel. Existing rows are preserved (ON CONFLICT DO NOTHING) so
// spend + operator-tuned caps survive restarts.
func seedTenantBudget(db *sql.DB, dia dialect.Kind, tenant string, shards int, capUSD float64) error {
	if shards < 1 {
		shards = 1
	}
	perShard := noCapSentinel
	if capUSD > 0 {
		perShard = capUSD / float64(shards)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	q := dia.Rebind(`INSERT INTO llm_budget_shard (tenant_id, shard, reserved, spent, cap)
			 VALUES (?, ?, 0, 0, ?) ON CONFLICT (tenant_id, shard) DO NOTHING`)
	for s := 0; s < shards; s++ {
		if _, err := db.ExecContext(ctx, q, tenant, s, perShard); err != nil {
			return err
		}
	}
	return nil
}

// keysFromEnv builds the broker-held provider key set (N1: keys live ONLY in
// the backend). P0 sources them from the backend's own env; BYO-key from
// tenant_provider_keys is P0.1.
func keysFromEnv(defaultProvider string) provider.StaticKeys {
	keys := provider.StaticKeys{}
	if k := os.Getenv("OPENAI_API_KEY"); k != "" {
		keys["openai"] = k
		keys["openai-compatible"] = k // shares the key unless a BYO endpoint overrides (P0.1)
	}
	// §30: each cloud provider uses its OWN key.
	if k := os.Getenv("GEMINI_API_KEY"); k != "" {
		keys["gemini"] = k
	}
	if k := os.Getenv("ANTHROPIC_API_KEY"); k != "" {
		keys["anthropic"] = k
	}
	// A local/custom default provider with no key of its own inherits the
	// OpenAI key (local servers like LM Studio simply ignore it); a provider
	// that already has its own key above keeps it.
	if _, ok := keys[defaultProvider]; !ok {
		if k := os.Getenv("OPENAI_API_KEY"); k != "" {
			keys[defaultProvider] = k
		}
	}
	return keys
}

// retrierClassifier treats provider-unavailable (conn/5xx) and rate-limited
// (429) as retryable; everything else is terminal.
type retrierClassifier struct{}

func (retrierClassifier) Retryable(err error) (bool, time.Duration) {
	if errors.Is(err, provider.ErrProviderUnavailable) || errors.Is(err, provider.ErrRateLimited) {
		return true, 0
	}
	return false, 0
}

// breakerCountsAsFailure is the per-(provider,model) breaker's failure
// classifier (§32.1 #1): only a provider-HEALTH failure counts toward tripping.
// The breaker wraps the retrier, so a drained retry budget on a transient error
// (ErrRetryBudgetExhausted) also counts — the provider WAS failing. Permanent
// client faults, usage-missing, and ctx cancellation are breaker-neutral.
func breakerCountsAsFailure(err error) bool {
	return provider.IsProviderHealthFailure(err) ||
		errors.Is(err, resilience.ErrRetryBudgetExhausted)
}

func retrierConfig() resilience.RetrierConfig {
	return resilience.RetrierConfig{
		Policy: resilience.RetryPolicy{
			MaxAttempts: 3, BaseBackoff: 200 * time.Millisecond,
			MaxBackoff: 5 * time.Second, RetryBudgetFraction: 0.1,
		},
		Classifier: retrierClassifier{},
		// Clock + Jitter default inside newRetrier.
	}
}
