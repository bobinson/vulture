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
	// upstream is the provider's OWN diagnosis, present only for the one class
	// whose body cannot echo request content (see provider/upstream_detail.go).
	// nil for every other error, and the key is then omitted from the wire
	// entirely — a consumer that does not know the field sees byte-identical
	// output for every error it already handles.
	upstream *upstreamInfo
}

// upstreamInfo is the borrowed half of the envelope. It is a VALUE on a copy of
// the static apiError, never a mutation of it: the package-level errors are
// shared across goroutines and writing to one would race and, worse, leak one
// request's upstream text into another's response.
type upstreamInfo struct {
	Provider string `json:"provider"`
	Status   int    `json:"status"`
	Message  string `json:"message"`
}

// withUpstream returns a COPY carrying the provider's diagnosis.
func (e *apiError) withUpstream(u *upstreamInfo) *apiError {
	c := *e
	c.upstream = u
	return &c
}

// Error implements error for wrapping/inspection; the message is static and
// secret-free (N6).
func (e *apiError) Error() string { return e.code + ": " + e.message }

// Static typed errors keyed by the §5 machine codes. Messages are fixed
// strings — they never interpolate request content (N6).
var (
	errUnauthorized        = &apiError{code: "unauthorized", message: "authentication required", status: http.StatusUnauthorized, retriable: false}
	errTokenExpired        = &apiError{code: "token_expired", message: "token expired", status: http.StatusUnauthorized, retriable: false}
	errTokenRevoked        = &apiError{code: "token_revoked", message: "token revoked", status: http.StatusUnauthorized, retriable: false}
	errRevocationUnavail   = &apiError{code: "revocation_unavailable", message: "revocation state unavailable", status: http.StatusServiceUnavailable, retriable: true}
	errBudgetExceeded      = &apiError{code: "budget_exceeded", message: "budget exceeded", status: http.StatusPaymentRequired, retriable: false}
	errInvalidRequest      = &apiError{code: "invalid_request", message: "invalid request", status: http.StatusBadRequest, retriable: false}
	errProviderUnavailable = &apiError{code: "provider_unavailable", message: "provider unavailable", status: http.StatusBadGateway, retriable: true}
	errRateLimited         = &apiError{code: "rate_limited", message: "rate limited", status: http.StatusTooManyRequests, retriable: true}
	// §32.1: PERMANENT provider faults — retriable=false so neither the broker
	// retrier nor the agent retries them (they would fail identically), and the
	// distinct codes surface the REAL cause instead of a generic outage.
	errProviderBadRequest   = &apiError{code: "provider_bad_request", message: "provider rejected the request", status: http.StatusBadGateway, retriable: false}
	errProviderAuth         = &apiError{code: "provider_auth_error", message: "provider authentication failed", status: http.StatusBadGateway, retriable: false}
	errModelNotFound        = &apiError{code: "model_not_found", message: "model not found or not routable", status: http.StatusBadGateway, retriable: false}
	errAllProvidersDown     = &apiError{code: "all_providers_down", message: "all providers unavailable", status: http.StatusServiceUnavailable, retriable: true}
	errProviderNotAllowlist = &apiError{code: "provider_unavailable", message: "provider not allowlisted", status: http.StatusBadGateway, retriable: false}
	errSSRFBlocked          = &apiError{code: "invalid_request", message: "egress target rejected", status: http.StatusBadRequest, retriable: false}
	errMethodNotAllowed     = &apiError{code: "invalid_request", message: "method not allowed", status: http.StatusMethodNotAllowed, retriable: false}
	errInternal             = &apiError{code: "provider_unavailable", message: "internal error", status: http.StatusBadGateway, retriable: true}
	// §26/H4: body exceeded the size cap.
	errRequestTooLarge = &apiError{code: "request_too_large", message: "request body too large", status: http.StatusRequestEntityTooLarge, retriable: false}
	// §9/H2: the model emitted more tool calls / larger aggregate arguments
	// than the per-turn bound — a prompt-injected model must not be able to
	// flood the broker's parser/ledger/stream.
	errToolOutputTooLarge = &apiError{code: "tool_output_too_large", message: "tool-call output exceeds the per-turn bound", status: http.StatusRequestEntityTooLarge, retriable: false}
	// §26/M6 + §5: streaming (F2) is not yet supported; reject rather than
	// silently downgrade a stream:true request to a non-stream response.
	errStreamUnsupported = &apiError{code: "invalid_request", message: "streaming responses are not supported", status: http.StatusBadRequest, retriable: false}
	// §5: the X-Vulture-Task-Type / X-Vulture-Request-Id metadata headers are
	// required (task_type gates scope; request_id is the idempotency/ledger PK).
	errMissingMetadata = &apiError{code: "invalid_request", message: "missing required X-Vulture metadata header", status: http.StatusBadRequest, retriable: false}
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
	// §32.1: permanent client/config faults FIRST — distinct, non-retriable
	// codes so a bad request/key/model is not relabeled a transient outage.
	{provider.ErrProviderBadRequest, errProviderBadRequest},
	{provider.ErrProviderAuth, errProviderAuth},
	{provider.ErrModelNotFound, errModelNotFound},
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

// mapProviderErrWithUpstream is mapProviderErr plus the provider's own message,
// for the class that allows it.
//
// Classification is delegated to mapProviderErr unchanged — the allowlist lives
// in the provider layer (upstreamAllowed), so the decision "may this text be
// returned" is made once, next to the body that would be returned, and not
// re-litigated here. This function only decides whether a message the provider
// layer already sanitised gets attached.
func mapProviderErrWithUpstream(err error) *apiError {
	base := mapProviderErr(err)
	var ue *provider.UpstreamError
	if !errors.As(err, &ue) || ue.Message == "" {
		return base
	}
	// Re-apply the allowlist at the point of PUBLICATION. A non-empty Message
	// is not proof the provider layer authorised it: UpstreamError is an
	// exported struct with independent Status and Message fields, so "the
	// producer already checked" is an invariant held in another package by
	// convention. The predicate is provider's own (not a second copy of the
	// list), so the two cannot disagree — this only ensures it is asked twice.
	if !provider.UpstreamDisclosable(ue.Status) {
		return base
	}
	return base.withUpstream(&upstreamInfo{
		Provider: ue.Provider, Status: ue.Status, Message: ue.Message,
	})
}
