// Package egress defines the LLM-broker egress-safety seam (feature 0064,
// §7/§9/§11): provider allowlisting, SSRF-safe validation of tenant BYO
// base URLs (resolve-then-pin against DNS rebinding, deny RFC1918 /
// link-local / loopback / IMDS), and the model-selection seam that
// re-applies residency/policy to every fallback candidate.

package egress

import "errors"

// Sentinel egress-safety errors.
var (
	// ErrProviderNotAllowed indicates the provider is not on the
	// configured allowlist (§7 residency / VULTURE_LLM_PROVIDER_ALLOWLIST).
	ErrProviderNotAllowed = errors.New("broker/egress: provider not allowed")
	// ErrSSRFBlocked indicates a base URL resolved to a forbidden
	// address (RFC1918 / link-local / loopback / IMDS) or failed
	// scheme/allowlist checks (§11 blocking #3).
	ErrSSRFBlocked = errors.New("broker/egress: SSRF blocked")
)

// PinnedTarget is the result of resolve-then-pin: the validated URL along
// with the exact IP the caller MUST dial to defeat DNS rebinding (§11).
type PinnedTarget struct {
	// URL is the validated https base URL.
	URL string
	// IP is the resolved, allow-checked address the transport must pin
	// the connection to (rebinding defense).
	IP string
	// Provider is the provider this target belongs to.
	Provider string
}

// SSRFValidator validates and pins outbound provider base URLs. It is
// applied to every use of a tenant BYO base_url (untrusted, §11).
type SSRFValidator interface {
	// Validate checks scheme (https only), allowlist membership, and
	// resolves the host, rejecting private/link-local/loopback/IMDS
	// ranges. It returns a PinnedTarget the transport dials directly.
	Validate(provider, baseURL string) (*PinnedTarget, error)
}

// Allowlist reports whether a provider may be egressed to
// (VULTURE_LLM_PROVIDER_ALLOWLIST, §7).
type Allowlist interface {
	// Allowed reports whether the named provider is permitted.
	Allowed(provider string) bool
}

// PolicyContext carries residency/policy inputs for model selection (§7).
// It is re-applied to EVERY fallback candidate so failover cannot egress
// cross-region or to a policy-incapable model.
type PolicyContext struct {
	Region   string
	PIITier  string
	CostDial string
	TaskType string
}

// Candidate is one egress candidate: a model plus the provider route it
// egresses through. Provider "" means the broker default; BaseURL "" means
// the provider's canonical default endpoint (§7).
type Candidate struct {
	Model    string
	Provider string
	BaseURL  string
}

// ModelSelection is the resolved primary model plus its ordered fallback
// chain (§7). Each entry has already passed residency/policy re-check.
// Routes, when set, is the authoritative per-candidate provider routing
// (tenant BYO base_url etc.); otherwise candidates derive from
// Model+Fallbacks with default routing.
type ModelSelection struct {
	Model     string
	Fallbacks []string
	Routes    []Candidate
}

// Candidates returns the ordered egress candidates, primary first. Explicit
// Routes are authoritative; otherwise Model+Fallbacks map to default-routed
// candidates. Every candidate is allowlist+SSRF re-checked at egress time —
// failover must never skip the gate (§7/§11).
func (s *ModelSelection) Candidates() []Candidate {
	if len(s.Routes) > 0 {
		return s.Routes
	}
	out := make([]Candidate, 0, 1+len(s.Fallbacks))
	out = append(out, Candidate{Model: s.Model})
	for _, m := range s.Fallbacks {
		out = append(out, Candidate{Model: m})
	}
	return out
}

// ModelSelector resolves a request to a model + fallback chain (§7),
// defaulting to provider.get_model()/FALLBACK_CHAINS semantics, optionally
// delegating to magicrouter.
type ModelSelector interface {
	// Select returns the model and fallback chain for the given hint
	// under the supplied policy context, with residency re-applied to
	// each candidate.
	Select(modelHint string, policy PolicyContext) (*ModelSelection, error)
}
