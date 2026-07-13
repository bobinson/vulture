// Package server defines the LLM-broker HTTP surface (feature 0064, §5):
// the internal-only OpenAI-compatible endpoints (/internal/v1/llm/complete
// and /internal/v1/llm/embed) plus the Dependencies wiring that composes
// the token, budget, egress, provider, and resilience seams. It also
// exposes the readiness ladder (§12).
package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/vulture/backend/internal/broker/budget"
	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/resilience"
	"github.com/vulture/backend/internal/broker/token"
)

// Dependencies composes every broker seam. The real server is constructed
// from a fully-populated Dependencies; module agents supply concrete
// implementations of each field. Adapters is keyed by provider name.
type Dependencies struct {
	// Verifier validates per-run tokens (§6).
	Verifier token.Verifier
	// Denylist is the emergency kid kill switch (§6/H3).
	Denylist token.Denylist
	// Revocation is the per-run jti kill switch checked per turn (M3).
	Revocation token.Revocation
	// Budget reserves/reconciles spend (§8).
	Budget budget.Manager
	// Selector resolves model + fallback chain with residency (§7).
	Selector egress.ModelSelector
	// SSRF validates + pins tenant BYO base URLs (§11).
	SSRF egress.SSRFValidator
	// Allowlist gates egress providers (§7).
	Allowlist egress.Allowlist
	// Adapters is the per-provider egress set (§9), keyed by name.
	Adapters map[string]provider.Adapter
	// Keys resolves the broker-held provider API keys (N1). Nil = no keys
	// (adapters send no Authorization header — local/keyless endpoints).
	Keys provider.KeyResolver
	// Breakers hands out the circuit breaker for a (provider,model) key —
	// one provider/model's failures never open another's circuit (§9).
	Breakers resilience.BreakerPool
	// Bulkheads hands out the per-provider bulkhead — one slow provider
	// cannot shed load for the others (§9).
	Bulkheads resilience.BulkheadPool
	// CallTimeoutSec bounds each provider call (§9/§16, VULTURE_LLM_CALL_TIMEOUT_SEC);
	// 0 disables the guard (test default).
	CallTimeoutSec int
	// DBHealth reports the budget store's health (§12 honest readiness) —
	// production wiring MUST set it (e.g. db.PingContext); a replica whose
	// store is down reports NOT ready. Nil skips the check (unit tests /
	// keyless dev wiring only).
	DBHealth func(ctx context.Context) error
	// Retriers hands out the per-provider retrier (§9/§26 M3) — one provider's
	// 429 storm drains only its own retry budget, never starving another's.
	Retriers resilience.RetrierPool
}

// ReadinessProbe reports whether a replica can serve (§12). NOTE: P0 checks
// only that >=1 provider adapter is CONFIGURED. The full §12/C1 ladder
// (provider health + PG-healthy-or-degraded-slice + revocation cache, draining
// to skills-only) is a tracked follow-up, not yet implemented.
type ReadinessProbe interface {
	// Ready reports readiness; the error explains why not, if not ready.
	Ready(ctx context.Context) (bool, error)
}

// Server is the broker HTTP server. It exposes the §5 endpoints and the
// readiness probe. It is internal-only (never ingress-exposed, §11).
type Server struct {
	deps Dependencies
}

// New constructs a Server from its dependencies. It does not start
// listening; the caller mounts Handler() / registers routes.
func New(deps Dependencies) *Server {
	return &Server{deps: deps}
}

// Deps exposes the wired dependencies (read-only accessor for tests).
func (s *Server) Deps() Dependencies { return s.deps }

// Handler returns the http.Handler exposing the internal broker routes (§5).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(completePath, s.HandleComplete)
	mux.HandleFunc(embedPath, s.HandleEmbed)
	mux.HandleFunc(livezPath, s.handleLivez)
	mux.HandleFunc(readyzPath, s.handleReadyz)
	return mux
}

// §5/§26 C1: genuine OpenAI wire paths — the agent's OpenAI SDK client, with
// base_url ending in /v1, derives these; the broker is internal-only.
const (
	completePath = "/v1/chat/completions"
	embedPath    = "/v1/embeddings"
	livezPath    = "/livez"
	readyzPath   = "/readyz"
)

// Ready implements ReadinessProbe (§12 honest readiness): a replica is ready
// when >=1 provider adapter is configured AND its budget store is healthy —
// a broker that cannot reserve budget cannot serve, and must say so instead
// of failing requests at reserve time. The §12 "degraded-reserve" slice
// (serving from a reserved budget tranche while PG is down) is deliberately
// DESCOPED for P0: not-ready → agents use their skills-only fallback, which
// is the honest degraded mode this deployment already has.
func (s *Server) Ready(ctx context.Context) (bool, error) {
	if len(s.deps.Adapters) == 0 {
		return false, errNoHealthyProvider
	}
	if s.deps.DBHealth != nil {
		if err := s.deps.DBHealth(ctx); err != nil {
			return false, errBudgetStoreDown
		}
	}
	return true, nil
}

var (
	errNoHealthyProvider = errors.New("broker/server: no healthy provider")
	// errBudgetStoreDown is a fixed, secret-free reason string (N6): the
	// underlying DB error is never surfaced on /readyz.
	errBudgetStoreDown = errors.New("broker/server: budget store unavailable")
)

func (s *Server) handleLivez(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ok, err := s.Ready(r.Context())
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false, "reason": safeReason(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ready": true})
}

// safeReason returns a redacted, secret-free reason string (N6).
func safeReason(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Compile-time interface assertion.
var _ ReadinessProbe = (*Server)(nil)
