// Test fakes for the broker server RED-phase contract tests (feature 0064,
// §5/§12). These are controllable fakes for the injected boundary
// interfaces (token / budget / egress / provider / resilience). They are
// NOT the package stubs: the package stubs always return ErrNotImplemented,
// which would make it impossible to exercise the handler's happy path.
// Fakes let each table row drive a specific behavior so the handler logic
// (not yet implemented) is what is under test.
package server_test

import (
	"context"
	"sync"

	"github.com/vulture/backend/internal/broker/budget"
	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/resilience"
	"github.com/vulture/backend/internal/broker/token"
)

// --- token fakes ---

type fakeVerifier struct {
	claims *token.Claims
	err    error
	calls  int
}

func (f *fakeVerifier) Verify(raw string) (*token.Claims, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

type fakeDenylist struct {
	denied map[string]bool
	err    error
}

func (f *fakeDenylist) IsDenied(kid string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.denied[kid], nil
}
func (f *fakeDenylist) Deny(kid string) error {
	if f.denied == nil {
		f.denied = map[string]bool{}
	}
	f.denied[kid] = true
	return nil
}

type fakeRevocation struct {
	revoked map[string]bool
	err     error
}

func (f *fakeRevocation) IsRevoked(jti string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.revoked[jti], nil
}
func (f *fakeRevocation) Revoke(jti string) error {
	if f.revoked == nil {
		f.revoked = map[string]bool{}
	}
	f.revoked[jti] = true
	return nil
}

// --- budget fakes ---

type fakeBudget struct {
	mu             sync.Mutex
	reserveErr     error
	reservation    *budget.Reservation
	reconciled     []budget.LedgerEntry
	reconcileErr   error
	remainingUSD   float64
	remainingErr   error
	reserveReqs    []budget.ReserveRequest
	reconcileCalls int
}

func (f *fakeBudget) Reserve(ctx context.Context, req budget.ReserveRequest) (*budget.Reservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reserveReqs = append(f.reserveReqs, req)
	if f.reserveErr != nil {
		return nil, f.reserveErr
	}
	if f.reservation != nil {
		return f.reservation, nil
	}
	return &budget.Reservation{
		RunID:         req.RunID,
		RequestID:     req.RequestID,
		TenantID:      req.TenantID,
		ReservedUSD:   req.EstimatedUSD,
		ModelSnapshot: req.ModelSnapshot,
	}, nil
}

func (f *fakeBudget) Reconcile(ctx context.Context, entry budget.LedgerEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reconcileCalls++
	if f.reconcileErr != nil {
		return f.reconcileErr
	}
	f.reconciled = append(f.reconciled, entry)
	return nil
}

func (f *fakeBudget) Remaining(ctx context.Context, tenantID string) (float64, error) {
	if f.remainingErr != nil {
		return 0, f.remainingErr
	}
	return f.remainingUSD, nil
}

func (f *fakeBudget) reconciledEntries() []budget.LedgerEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]budget.LedgerEntry, len(f.reconciled))
	copy(out, f.reconciled)
	return out
}

func (f *fakeBudget) reserveRequests() []budget.ReserveRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]budget.ReserveRequest, len(f.reserveReqs))
	copy(out, f.reserveReqs)
	return out
}

// --- egress fakes ---

type fakeSelector struct {
	sel    *egress.ModelSelection
	err    error
	policy egress.PolicyContext
}

func (f *fakeSelector) Select(modelHint string, policy egress.PolicyContext) (*egress.ModelSelection, error) {
	f.policy = policy
	if f.err != nil {
		return nil, f.err
	}
	if f.sel != nil {
		return f.sel, nil
	}
	m := modelHint
	if m == "" {
		m = "gpt-4o"
	}
	return &egress.ModelSelection{Model: m}, nil
}

type fakeSSRF struct {
	target    *egress.PinnedTarget
	err       error
	baseURLs  []string
	providers []string
}

func (f *fakeSSRF) Validate(prov, baseURL string) (*egress.PinnedTarget, error) {
	f.baseURLs = append(f.baseURLs, baseURL)
	f.providers = append(f.providers, prov)
	if f.err != nil {
		return nil, f.err
	}
	if f.target != nil {
		return f.target, nil
	}
	return &egress.PinnedTarget{URL: baseURL, IP: "203.0.113.10", Provider: prov}, nil
}

type fakeAllowlist struct {
	allow map[string]bool
	all   bool
}

func (f *fakeAllowlist) Allowed(prov string) bool {
	if f.all {
		return true
	}
	return f.allow[prov]
}

// --- provider fakes ---

type fakeAdapter struct {
	name        string
	resp        *provider.CompletionResponse
	err         error
	embedResp   *provider.EmbeddingResponse
	embedErr    error
	completeReq *provider.CompletionRequest
	seenCreds   provider.Credentials
}

func (f *fakeAdapter) Name() string { return f.name }

func (f *fakeAdapter) Complete(ctx context.Context, creds provider.Credentials, req provider.CompletionRequest) (*provider.CompletionResponse, error) {
	r := req
	f.completeReq = &r
	f.seenCreds = creds
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func (f *fakeAdapter) Stream(ctx context.Context, creds provider.Credentials, req provider.CompletionRequest) (<-chan provider.StreamChunk, error) {
	return nil, provider.ErrNotImplemented
}

func (f *fakeAdapter) Embed(ctx context.Context, creds provider.Credentials, req provider.EmbeddingRequest) (*provider.EmbeddingResponse, error) {
	if f.embedErr != nil {
		return nil, f.embedErr
	}
	return f.embedResp, nil
}

// --- resilience fakes ---

// passthroughBreaker executes fn directly (closed circuit) unless forced open.
type passthroughBreaker struct {
	state    resilience.CircuitState
	forceErr error
}

func (b *passthroughBreaker) Execute(ctx context.Context, fn resilience.Call) error {
	if b.forceErr != nil {
		return b.forceErr
	}
	return fn(ctx)
}
func (b *passthroughBreaker) State() resilience.CircuitState { return b.state }

type passthroughBulkhead struct {
	forceErr error
}

func (b *passthroughBulkhead) Execute(ctx context.Context, fn resilience.Call) error {
	if b.forceErr != nil {
		return b.forceErr
	}
	return fn(ctx)
}
func (b *passthroughBulkhead) InFlight() int { return 0 }

type passthroughRetrier struct {
	forceErr error
}

func (b *passthroughRetrier) Execute(ctx context.Context, fn resilience.Call) error {
	if b.forceErr != nil {
		return b.forceErr
	}
	return fn(ctx)
}

// singleBreakerPool hands the same breaker to every key (legacy single-
// instance tests keep their forceErr semantics).
type singleBreakerPool struct{ b resilience.CircuitBreaker }

func (p singleBreakerPool) For(string) resilience.CircuitBreaker { return p.b }

// singleBulkheadPool hands the same bulkhead to every key.
type singleBulkheadPool struct{ b resilience.Bulkhead }

func (p singleBulkheadPool) For(string) resilience.Bulkhead { return p.b }

// keyedBreakerPool returns a per-key breaker from m, or def when absent —
// lets a test open ONE (provider,model) circuit while others stay closed.
type keyedBreakerPool struct {
	m   map[string]resilience.CircuitBreaker
	def resilience.CircuitBreaker
}

func (p *keyedBreakerPool) For(key string) resilience.CircuitBreaker {
	if b, ok := p.m[key]; ok {
		return b
	}
	return p.def
}

// compile-time assertions that fakes satisfy the seams.
var (
	_ token.Verifier            = (*fakeVerifier)(nil)
	_ token.Denylist            = (*fakeDenylist)(nil)
	_ token.Revocation          = (*fakeRevocation)(nil)
	_ budget.Manager            = (*fakeBudget)(nil)
	_ egress.ModelSelector      = (*fakeSelector)(nil)
	_ egress.SSRFValidator      = (*fakeSSRF)(nil)
	_ egress.Allowlist          = (*fakeAllowlist)(nil)
	_ provider.Adapter          = (*fakeAdapter)(nil)
	_ resilience.CircuitBreaker = (*passthroughBreaker)(nil)
	_ resilience.Bulkhead       = (*passthroughBulkhead)(nil)
	_ resilience.Retrier        = (*passthroughRetrier)(nil)
	_ resilience.BreakerPool    = singleBreakerPool{}
	_ resilience.BreakerPool    = (*keyedBreakerPool)(nil)
	_ resilience.BulkheadPool   = singleBulkheadPool{}
)
