// Package token defines the LLM-broker per-run token model (feature 0064,
// §6): asymmetric ES256/EdDSA JWTs minted by the orchestrator (private
// key) and verified by broker replicas (public JWKS). It also defines the
// emergency-kill seams — a kid Denylist and a per-run jti Revocation store
// — checked at every verify / turn boundary.
package token

import "errors"

// Sentinel verification errors. These map onto the §5 API error codes
// (unauthorized / token_expired / token_revoked).
var (
	// ErrUnauthorized covers a malformed, unsigned, wrong-kid, or
	// otherwise unverifiable token.
	ErrUnauthorized = errors.New("broker/token: unauthorized")
	// ErrTokenExpired is returned when exp is in the past (after skew).
	ErrTokenExpired = errors.New("broker/token: token expired")
	// ErrTokenRevoked is returned when the jti is in the revocation set.
	ErrTokenRevoked = errors.New("broker/token: token revoked")
	// ErrKidDenied is returned when the token's kid is on the denylist
	// (emergency mint-key revocation, §6/H3).
	ErrKidDenied = errors.New("broker/token: kid denied")
	// ErrRevocationUnavailable is returned when revocation state cannot
	// be resolved (fail-CLOSED for that one call, §12).
	ErrRevocationUnavailable = errors.New("broker/token: revocation unavailable")
)

// Claims is the verified payload of a per-run broker token (§6).
type Claims struct {
	// Subject is the run_id (JWT sub).
	Subject string `json:"sub"`
	// TenantID scopes keys/budgets/cache/ledger/residency (N8).
	TenantID string `json:"tenant_id"`
	// Scope authorizes specific task_type/model combinations.
	Scope []string `json:"scope"`
	// BudgetRef references the tenant budget this run charges against.
	BudgetRef string `json:"budget_ref"`
	// Region is the residency region re-applied to every fallback (§7).
	Region string `json:"region"`
	// IssuedAt is the JWT iat (unix seconds).
	IssuedAt int64 `json:"iat"`
	// ExpiresAt is the JWT exp (unix seconds).
	ExpiresAt int64 `json:"exp"`
	// JTI is the unique token id, used for revocation (§6, M3).
	JTI string `json:"jti"`
	// KID is the signing-key id carried in the JWT header; checked
	// against the Denylist and used to select the JWKS verify key.
	KID string `json:"kid"`
}

// AllowsScope reports whether the token grants the given required scope
// (e.g. "scan:gpt-4o"). The server uses this to enforce per-request scope
// against the actual task_type:model (H1) — the scope claim is authoritative.
func (c *Claims) AllowsScope(required string) bool {
	return scopeSatisfied(c.Scope, []string{required})
}

// MintRequest is the orchestrator-side input to mint a per-run token.
type MintRequest struct {
	RunID     string
	TenantID  string
	Scope     []string
	BudgetRef string
	Region    string
	// TTL is the token lifetime; prefer short exp + refresh (§6).
	TTLSeconds int64
}

// Minter is the orchestrator-only seam that signs per-run tokens with the
// private mint key. Broker replicas MUST NOT hold a Minter (N1/§6).
type Minter interface {
	// Mint issues a signed token string for the given request.
	Mint(req MintRequest) (string, error)
}

// Verifier is the broker-replica seam that verifies a token against the
// public JWKS, enforcing kid/exp/jti/scope/tenant and the kid denylist
// (§6). It consults Denylist and Revocation on every verify.
type Verifier interface {
	// Verify parses and validates the raw token, returning its claims
	// or one of the sentinel errors above.
	Verify(raw string) (*Claims, error)
}

// Denylist is the emergency mint-key kill seam (§6/H3): a compromised kid
// is added here and checked on every verify, so forged tokens are rejected
// fleet-wide within a short JWKS-refresh TTL.
type Denylist interface {
	// IsDenied reports whether a signing-key id is revoked. On backing
	// store failure it should surface ErrRevocationUnavailable so the
	// caller can fail-CLOSED.
	IsDenied(kid string) (bool, error)
	// Deny adds a kid to the denylist (emergency revocation).
	Deny(kid string) error
}

// Revocation is the per-run jti kill seam (§6, M3): a jti is revoked on
// run end/cancel and checked at every turn boundary. Implementations back
// this with revoked_jti plus a bounded local cache for degraded mode (§12).
type Revocation interface {
	// IsRevoked reports whether a jti has been revoked. On backing store
	// failure with no cached answer it should surface
	// ErrRevocationUnavailable so the caller fails-CLOSED for that call.
	IsRevoked(jti string) (bool, error)
	// Revoke marks a jti revoked (run end/cancel).
	Revoke(jti string) error
}
