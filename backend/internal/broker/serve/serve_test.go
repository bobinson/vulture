package serve

import (
	"testing"
	"time"

	"github.com/vulture/backend/internal/broker/token"
)

// fake kill-store seams so the verifier can run without a DB.
type fakeStore struct{ revoked map[string]bool }

func (fakeStore) IsDenied(string) (bool, error) { return false, nil }
func (fakeStore) Deny(string) error             { return nil }
func (f *fakeStore) IsRevoked(jti string) (bool, error) {
	return f.revoked[jti], nil
}
func (f *fakeStore) Revoke(jti string) error {
	if f.revoked == nil {
		f.revoked = map[string]bool{}
	}
	f.revoked[jti] = true
	return nil
}

// newTestBroker assembles a Broker with a real ephemeral keypair + real
// mint/verify, and a fake revocation store, so mint/verify/revoke can be
// exercised without Postgres.
func newTestBroker(t *testing.T) (*Broker, *fakeStore) {
	t.Helper()
	priv, pub, err := resolveKeypair("")
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	minter, err := token.NewMinter(priv, brokerKID)
	if err != nil {
		t.Fatalf("minter: %v", err)
	}
	store := &fakeStore{}
	verifier, err := token.NewVerifier(map[string][]byte{brokerKID: pub}, store, store)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return &Broker{
		Enabled: true, minter: minter, revocation: store, verify: verifier,
		region: "local", ttl: time.Hour, runJTIs: map[string][]string{},
	}, store
}

func TestResolveKeypair_EphemeralRoundTrips(t *testing.T) {
	b, _ := newTestBroker(t)
	tok, err := b.MintForAgent("run-1", "scan", "gpt-4o")
	if err != nil || tok == "" {
		t.Fatalf("mint = %q,%v", tok, err)
	}
	claims, err := b.verify.Verify(tok)
	if err != nil {
		t.Fatalf("verify freshly-minted token: %v", err)
	}
	if claims.Subject != "run-1" {
		t.Errorf("sub = %q, want run-1", claims.Subject)
	}
	if !claims.AllowsScope("scan:gpt-4o") {
		t.Errorf("scope %v does not allow scan:gpt-4o", claims.Scope)
	}
	if claims.AllowsScope("prove:gpt-4o") {
		t.Errorf("scope %v must NOT allow an unrelated task_type", claims.Scope)
	}
}

func TestMintForAgent_TracksJTI_RevokeRunRevokesIt(t *testing.T) {
	b, store := newTestBroker(t)
	tok, _ := b.MintForAgent("run-9", "scan", "gpt-4o")
	claims, _ := b.verify.Verify(tok)

	// The jti is tracked under the run.
	b.mu.Lock()
	tracked := append([]string(nil), b.runJTIs["run-9"]...)
	b.mu.Unlock()
	if len(tracked) != 1 || tracked[0] != claims.JTI {
		t.Fatalf("tracked jtis = %v, want [%s]", tracked, claims.JTI)
	}

	b.RevokeRun("run-9")
	if !store.revoked[claims.JTI] {
		t.Fatalf("RevokeRun did not revoke jti %s", claims.JTI)
	}
	// The run entry is cleared after revoke.
	b.mu.Lock()
	_, present := b.runJTIs["run-9"]
	b.mu.Unlock()
	if present {
		t.Error("run entry not cleared after RevokeRun")
	}
}

func TestDisabledBroker_MintAndRevokeAreNoops(t *testing.T) {
	b := Disabled()
	tok, err := b.MintForAgent("r", "scan", "m")
	if err != nil || tok != "" {
		t.Fatalf("disabled mint = %q,%v want \"\",nil (Mode A)", tok, err)
	}
	b.RevokeRun("r") // must not panic
}

func TestAllowlistOrDefault(t *testing.T) {
	if got := allowlistOrDefault(nil); len(got) != 1 || got[0] != "openai" {
		t.Fatalf("empty allowlist default = %v, want [openai]", got)
	}
	if got := allowlistOrDefault([]string{"anthropic"}); len(got) != 1 || got[0] != "anthropic" {
		t.Fatalf("configured allowlist = %v, want [anthropic]", got)
	}
}

func TestRetrierClassifier(t *testing.T) {
	c := retrierClassifier{}
	// non-retryable sentinel
	if ok, _ := c.Retryable(token.ErrRevocationUnavailable); ok {
		t.Error("revocation-unavailable must not be retryable")
	}
}
