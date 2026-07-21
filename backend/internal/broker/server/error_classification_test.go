package server

import (
	"testing"

	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/resilience"
)

// §32.1 recurrence guardrail #2 — the classification table lock. For every
// egress sentinel, pin (a) the client-facing error code, (b) retriable, and
// (c) failover-eligibility. A new status/sentinel cannot silently fall into the
// retriable/failover bucket (the defect that turned a 400 into all_providers_down)
// without this table failing.
func TestErrorClassificationTable(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantCode  string
		retriable bool
		failover  bool
	}{
		{"rate_limited", provider.ErrRateLimited, "rate_limited", true, false},
		{"provider_unavailable", provider.ErrProviderUnavailable, "provider_unavailable", true, true},
		{"bad_request", provider.ErrProviderBadRequest, "provider_bad_request", false, false},
		{"auth", provider.ErrProviderAuth, "provider_auth_error", false, false},
		{"model_not_found", provider.ErrModelNotFound, "model_not_found", false, false},
		{"circuit_open", resilience.ErrCircuitOpen, "all_providers_down", true, true},
		{"budget_exhausted", resilience.ErrRetryBudgetExhausted, "provider_unavailable", true, false},
		{"bulkhead_full", resilience.ErrBulkheadFull, "rate_limited", true, false},
	}
	for _, c := range cases {
		ae := mapProviderErr(c.err)
		if ae.code != c.wantCode {
			t.Errorf("%s: code = %q, want %q", c.name, ae.code, c.wantCode)
		}
		if ae.retriable != c.retriable {
			t.Errorf("%s: retriable = %v, want %v", c.name, ae.retriable, c.retriable)
		}
		if got := isFailover(c.err); got != c.failover {
			t.Errorf("%s: isFailover = %v, want %v", c.name, got, c.failover)
		}
	}
}

// Permanent client faults must never be retriable and never fail over — a
// retry/failover would fail identically and (pre-fix) burned the retry budget +
// tripped the breaker.
func TestPermanentErrorsNeverRetriableOrFailover(t *testing.T) {
	for _, e := range []error{provider.ErrProviderBadRequest, provider.ErrProviderAuth, provider.ErrModelNotFound} {
		if mapProviderErr(e).retriable {
			t.Errorf("%v must be non-retriable", e)
		}
		if isFailover(e) {
			t.Errorf("%v must not fail over", e)
		}
		if !provider.IsPermanent(e) {
			t.Errorf("%v must be IsPermanent", e)
		}
	}
}
