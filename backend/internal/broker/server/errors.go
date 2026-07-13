package server

import (
	"errors"
	"net/http"

	"github.com/vulture/backend/internal/broker/budget"
	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/resilience"
	"github.com/vulture/backend/internal/broker/token"
)

// apiError is the structured, secret-free typed-error contract (§5/N6). It
// carries a stable machine code, a static human message, an HTTP status, and
// a retriable flag. It NEVER embeds a prompt, tool-call argument, or key.
type apiError struct {
	code      string
	message   string
	status    int
	retriable bool
}

// Error implements error for wrapping/inspection; the message is static and
// secret-free (N6).
func (e *apiError) Error() string { return e.code + ": " + e.message }

// Static typed errors keyed by the §5 machine codes. Messages are fixed
// strings — they never interpolate request content (N6).
var (
	errUnauthorized         = &apiError{"unauthorized", "authentication required", http.StatusUnauthorized, false}
	errTokenExpired         = &apiError{"token_expired", "token expired", http.StatusUnauthorized, false}
	errTokenRevoked         = &apiError{"token_revoked", "token revoked", http.StatusUnauthorized, false}
	errRevocationUnavail    = &apiError{"revocation_unavailable", "revocation state unavailable", http.StatusServiceUnavailable, true}
	errBudgetExceeded       = &apiError{"budget_exceeded", "budget exceeded", http.StatusPaymentRequired, false}
	errInvalidRequest       = &apiError{"invalid_request", "invalid request", http.StatusBadRequest, false}
	errProviderUnavailable  = &apiError{"provider_unavailable", "provider unavailable", http.StatusBadGateway, true}
	errRateLimited          = &apiError{"rate_limited", "rate limited", http.StatusTooManyRequests, true}
	errAllProvidersDown     = &apiError{"all_providers_down", "all providers unavailable", http.StatusServiceUnavailable, true}
	errProviderNotAllowlist = &apiError{"provider_unavailable", "provider not allowlisted", http.StatusBadGateway, false}
	errSSRFBlocked          = &apiError{"invalid_request", "egress target rejected", http.StatusBadRequest, false}
	errMethodNotAllowed     = &apiError{"invalid_request", "method not allowed", http.StatusMethodNotAllowed, false}
	errInternal             = &apiError{"provider_unavailable", "internal error", http.StatusBadGateway, true}
)

// errCase pairs a sentinel with the typed apiError it maps to. Tables keep
// the map* helpers to a single loop (cyclomatic complexity 2, DRY).
type errCase struct {
	sentinel error
	api      *apiError
}

// lookupErr returns the first matching table entry's apiError, or fallback.
func lookupErr(table []errCase, err error, fallback *apiError) *apiError {
	for _, c := range table {
		if errors.Is(err, c.sentinel) {
			return c.api
		}
	}
	return fallback
}

var tokenErrTable = []errCase{
	{token.ErrTokenExpired, errTokenExpired},
	{token.ErrTokenRevoked, errTokenRevoked},
	// M1: kid-denied maps to a generic unauthorized (do NOT leak "key revoked"
	// to an attacker) — mapped explicitly rather than via silent fall-through.
	{token.ErrKidDenied, errUnauthorized},
	{token.ErrRevocationUnavailable, errRevocationUnavail},
}

// mapTokenErr translates a token-verification/revocation sentinel into a
// typed apiError. Unknown/ErrUnauthorized → unauthorized.
func mapTokenErr(err error) *apiError {
	return lookupErr(tokenErrTable, err, errUnauthorized)
}

var providerErrTable = []errCase{
	{provider.ErrRateLimited, errRateLimited},
	{resilience.ErrBulkheadFull, errRateLimited},
	{resilience.ErrCircuitOpen, errAllProvidersDown},
	{resilience.ErrRetryBudgetExhausted, errProviderUnavailable},
}

// mapProviderErr translates a provider/resilience egress error into a typed
// apiError. Unknown/ErrProviderUnavailable/ErrUsageMissing → provider_unavailable.
func mapProviderErr(err error) *apiError {
	return lookupErr(providerErrTable, err, errProviderUnavailable)
}

// mapBudgetErr translates a budget error into a typed apiError.
func mapBudgetErr(err error) *apiError {
	if errors.Is(err, budget.ErrBudgetExceeded) {
		return errBudgetExceeded
	}
	return errInternal
}

// mapEgressErr translates an egress (allowlist/SSRF) error into a typed
// apiError.
func mapEgressErr(err error) *apiError {
	if errors.Is(err, egress.ErrSSRFBlocked) {
		return errSSRFBlocked
	}
	return errProviderNotAllowlist
}
