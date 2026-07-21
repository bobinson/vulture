package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// §32.1 #3: a cancelled/expired context (client disconnect or self-imposed
// CallTimeoutSec) must surface as the RAW context error — NOT wrapped as
// ErrProviderUnavailable — so it is non-retriable and breaker-neutral. Asserted
// per adapter since each has its own transport-error path.
func TestAdapters_CtxCancel_NotProviderUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	req := CompletionRequest{Model: "m", Messages: []Message{{Role: "user", Content: "x"}}}
	adapters := map[string]Adapter{
		"openai":    NewOpenAIAdapter(srv.Client()),
		"gemini":    NewGeminiAdapter(srv.Client()),
		"anthropic": NewAnthropicAdapter(srv.Client()),
	}
	for name, a := range adapters {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // already cancelled → Do() fails with ctx error
		_, err := a.Complete(ctx, Credentials{Provider: name, APIKey: "k", BaseURL: srv.URL}, req)
		if err == nil {
			t.Errorf("%s: expected error on cancelled ctx", name)
			continue
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%s: got %v, want errors.Is context.Canceled", name, err)
		}
		if errors.Is(err, ErrProviderUnavailable) {
			t.Errorf("%s: ctx-cancel must NOT be ErrProviderUnavailable (got %v)", name, err)
		}
		if IsProviderHealthFailure(err) {
			t.Errorf("%s: ctx-cancel must be breaker-neutral", name)
		}
	}
}

// §32.1 error taxonomy: statusError must map each upstream HTTP status onto a
// sentinel whose retry/failover/breaker semantics are correct. A permanent
// client-caused status (400/401/403/404/409/413/422) must NOT be retriable
// ErrProviderUnavailable — that is what caused the 9× retry + false
// all_providers_down cascade.
func TestStatusError_Classification(t *testing.T) {
	cases := []struct {
		status int
		want   error // nil == success
	}{
		{200, nil},
		{204, nil},
		{299, nil},
		{429, ErrRateLimited},
		{408, ErrProviderUnavailable}, // request timeout is transient
		{500, ErrProviderUnavailable},
		{502, ErrProviderUnavailable},
		{503, ErrProviderUnavailable},
		{400, ErrProviderBadRequest},
		{413, ErrProviderBadRequest},
		{422, ErrProviderBadRequest},
		{401, ErrProviderAuth},
		{403, ErrProviderAuth},
		{404, ErrModelNotFound},
		{409, ErrModelNotFound},
		{418, ErrProviderBadRequest}, // unknown 4xx → treat as permanent client fault
	}
	for _, c := range cases {
		got := statusError(c.status)
		if c.want == nil {
			if got != nil {
				t.Errorf("status %d: got %v, want nil", c.status, got)
			}
			continue
		}
		if !errors.Is(got, c.want) {
			t.Errorf("status %d: got %v, want errors.Is %v", c.status, got, c.want)
		}
	}
}

// Permanent client errors must be classified permanent (not retriable) and must
// NOT be provider-health failures (so the breaker stays closed on a bad request
// / bad key), while transient errors are the opposite.
func TestErrorClassificationHelpers(t *testing.T) {
	permanent := []error{ErrProviderBadRequest, ErrProviderAuth, ErrModelNotFound}
	for _, e := range permanent {
		if !IsPermanent(e) {
			t.Errorf("%v must be IsPermanent", e)
		}
		if IsProviderHealthFailure(e) {
			t.Errorf("%v must NOT be a provider-health failure (breaker-neutral)", e)
		}
	}
	transient := []error{ErrProviderUnavailable, ErrRateLimited}
	for _, e := range transient {
		if IsPermanent(e) {
			t.Errorf("%v must NOT be IsPermanent", e)
		}
		if !IsProviderHealthFailure(e) {
			t.Errorf("%v must be a provider-health failure (counts toward breaker)", e)
		}
	}
	// usage-missing and context cancellation are neither retriable nor
	// provider-health failures — a valid-but-unmetered response or a
	// self-imposed deadline is not the provider's fault.
	for _, e := range []error{ErrUsageMissing, context.Canceled, context.DeadlineExceeded} {
		if IsProviderHealthFailure(e) {
			t.Errorf("%v must be breaker-neutral", e)
		}
	}
}
