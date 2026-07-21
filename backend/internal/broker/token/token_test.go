package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test doubles for the injected external boundaries (denylist / revocation).
// These are in-memory fakes — the only things we legitimately mock (§6 says
// denylist + revocation are injected interfaces; no DB in this package).
// ---------------------------------------------------------------------------

// fakeDenylist is an in-memory Denylist. If err is set, both methods return it
// (models a backing-store outage so we can exercise fail-CLOSED).
type fakeDenylist struct {
	mu      sync.Mutex
	denied  map[string]bool
	err     error
	callErr error // returned by IsDenied only (store-outage on read path)
}

func newFakeDenylist(kids ...string) *fakeDenylist {
	d := &fakeDenylist{denied: map[string]bool{}}
	for _, k := range kids {
		d.denied[k] = true
	}
	return d
}

func (d *fakeDenylist) IsDenied(kid string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.callErr != nil {
		return false, d.callErr
	}
	return d.denied[kid], nil
}

func (d *fakeDenylist) Deny(kid string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	d.denied[kid] = true
	return nil
}

// fakeRevocation is an in-memory Revocation. callErr models a store outage on
// the read path (no cached answer) so we can exercise fail-CLOSED (§12).
type fakeRevocation struct {
	mu      sync.Mutex
	revoked map[string]bool
	callErr error
}

func newFakeRevocation(jtis ...string) *fakeRevocation {
	r := &fakeRevocation{revoked: map[string]bool{}}
	for _, j := range jtis {
		r.revoked[j] = true
	}
	return r
}

func (r *fakeRevocation) IsRevoked(jti string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.callErr != nil {
		return false, r.callErr
	}
	return r.revoked[jti], nil
}

func (r *fakeRevocation) Revoke(jti string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[jti] = true
	return nil
}

// ---------------------------------------------------------------------------
// Key helpers — real ES256 (P-256) keypairs, PEM encoded. No new dependency.
// ---------------------------------------------------------------------------

func genKeyPEM(t *testing.T) (privPEM, pubPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal priv: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privPEM, pubPEM
}

// fixedClock returns a Now func pinned to t.
func fixedClock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

// baseMintReq is a valid mint request template.
func baseMintReq() MintRequest {
	return MintRequest{
		RunID:      "run-abc",
		TenantID:   "tenant-1",
		Scope:      []string{"owasp:gpt-4o", "cwe:gpt-4o"},
		BudgetRef:  "budget-xyz",
		Region:     "us-east-1",
		TTLSeconds: 300,
	}
}

// mustMint builds a minter for kid and mints a token, failing the test on error.
func mustMint(t *testing.T, privPEM []byte, kid string, req MintRequest) string {
	t.Helper()
	m, err := NewMinter(privPEM, kid)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	tok, err := m.Mint(req)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok == "" {
		t.Fatalf("Mint returned empty token")
	}
	return tok
}

// ---------------------------------------------------------------------------
// Happy path: mint → verify round trip preserves all claims (§6).
// ---------------------------------------------------------------------------

func TestMintVerifyRoundTrip(t *testing.T) {
	privPEM, pubPEM := genKeyPEM(t)
	const kid = "kid-1"
	now := time.Unix(1_800_000_000, 0)

	req := baseMintReq()
	tok := mustMint(t, privPEM, kid, req)

	v, err := NewVerifier(
		map[string][]byte{kid: pubPEM},
		newFakeDenylist(),
		newFakeRevocation(),
		VerifierOptions{Now: fixedClock(now.Add(1 * time.Second))},
	)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if claims == nil {
		t.Fatal("Verify returned nil claims")
	}
	if claims.Subject != req.RunID {
		t.Errorf("Subject = %q, want %q", claims.Subject, req.RunID)
	}
	if claims.TenantID != req.TenantID {
		t.Errorf("TenantID = %q, want %q", claims.TenantID, req.TenantID)
	}
	if claims.BudgetRef != req.BudgetRef {
		t.Errorf("BudgetRef = %q, want %q", claims.BudgetRef, req.BudgetRef)
	}
	if claims.Region != req.Region {
		t.Errorf("Region = %q, want %q", claims.Region, req.Region)
	}
	if strings.Join(claims.Scope, ",") != strings.Join(req.Scope, ",") {
		t.Errorf("Scope = %v, want %v", claims.Scope, req.Scope)
	}
	if claims.KID != kid {
		t.Errorf("KID = %q, want %q", claims.KID, kid)
	}
	if claims.JTI == "" {
		t.Error("JTI must be populated for revocation")
	}
	if claims.ExpiresAt <= claims.IssuedAt {
		t.Errorf("exp (%d) must be after iat (%d)", claims.ExpiresAt, claims.IssuedAt)
	}
}

// Each mint must produce a unique jti so per-run revocation is precise (§6/M3).
func TestMintProducesUniqueJTI(t *testing.T) {
	privPEM, pubPEM := genKeyPEM(t)
	const kid = "kid-1"
	m, err := NewMinter(privPEM, kid)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	tok1, err := m.Mint(baseMintReq())
	if err != nil {
		t.Fatalf("Mint 1: %v", err)
	}
	tok2, err := m.Mint(baseMintReq())
	if err != nil {
		t.Fatalf("Mint 2: %v", err)
	}
	// Verify clock consistent with the pinned mint clock (TestMain) so the
	// freshly-minted token is neither not-yet-valid nor expired.
	v, err := NewVerifier(map[string][]byte{kid: pubPEM}, newFakeDenylist(), newFakeRevocation(),
		VerifierOptions{Now: fixedClock(time.Unix(1_800_000_000, 0).Add(time.Second))})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	c1, err := v.Verify(tok1)
	if err != nil {
		t.Fatalf("Verify 1: %v", err)
	}
	c2, err := v.Verify(tok2)
	if err != nil {
		t.Fatalf("Verify 2: %v", err)
	}
	if c1.JTI == c2.JTI {
		t.Errorf("two mints shared jti %q; must be unique per run", c1.JTI)
	}
}

// ---------------------------------------------------------------------------
// Security / edge cases (table-driven).  These build a valid token then
// perturb it, and assert Verify maps each attack to the specified sentinel.
// ---------------------------------------------------------------------------

func TestVerifyRejects(t *testing.T) {
	privPEM, pubPEM := genKeyPEM(t)
	// A second, attacker-controlled keypair (unknown to the verifier's JWKS).
	otherPriv, _ := genKeyPEM(t)
	const kid = "kid-1"
	now := time.Unix(1_800_000_000, 0)

	tests := []struct {
		name string
		// token builds the raw token under test given the good private PEM.
		token func(t *testing.T) string
		// denylist / revocation seams the verifier is built with.
		denylist   *fakeDenylist
		revocation *fakeRevocation
		opts       VerifierOptions
		wantErr    error
	}{
		{
			name: "expired token",
			token: func(t *testing.T) string {
				r := baseMintReq()
				r.TTLSeconds = 60
				return mustMint(t, privPEM, kid, r)
			},
			// Clock pushed well past exp + skew.
			opts:    VerifierOptions{Now: fixedClock(now.Add(1 * time.Hour))},
			wantErr: ErrTokenExpired,
		},
		{
			name: "within clock-skew leeway is still valid",
			token: func(t *testing.T) string {
				r := baseMintReq()
				r.TTLSeconds = 60
				return mustMint(t, privPEM, kid, r)
			},
			// 20s past exp but inside the 30s default skew ⇒ NOT expired.
			opts:    VerifierOptions{Now: fixedClock(now.Add(60*time.Second + 20*time.Second))},
			wantErr: nil,
		},
		{
			name: "kid on denylist (emergency mint-key kill)",
			token: func(t *testing.T) string {
				return mustMint(t, privPEM, kid, baseMintReq())
			},
			denylist: newFakeDenylist(kid),
			wantErr:  ErrKidDenied,
		},
		{
			name: "jti revoked (per-run kill)",
			token: func(t *testing.T) string {
				return mustMint(t, privPEM, kid, baseMintReq())
			},
			revocation: newFakeRevocation("__will_be_set__"),
			wantErr:    ErrTokenRevoked,
		},
		{
			name: "unknown kid (no matching JWKS key)",
			token: func(t *testing.T) string {
				return mustMint(t, privPEM, "kid-unknown", baseMintReq())
			},
			wantErr: ErrUnauthorized,
		},
		{
			name: "signature forged with attacker key (public-key forge attempt)",
			token: func(t *testing.T) string {
				// Attacker mints with their OWN private key but claims the
				// trusted kid. Verifier's public key for kid must reject it.
				return mustMint(t, otherPriv, kid, baseMintReq())
			},
			wantErr: ErrUnauthorized,
		},
		{
			name: "tampered payload (claims edited after signing)",
			token: func(t *testing.T) string {
				tok := mustMint(t, privPEM, kid, baseMintReq())
				return tamperTenant(t, tok, "tenant-EVIL")
			},
			wantErr: ErrUnauthorized,
		},
		{
			name: "alg none downgrade attack",
			token: func(t *testing.T) string {
				return forgeAlgNone(t, kid, baseMintReq())
			},
			wantErr: ErrUnauthorized,
		},
		{
			name: "garbage / non-JWT string",
			token: func(t *testing.T) string {
				return "not-a-jwt.at-all"
			},
			wantErr: ErrUnauthorized,
		},
		{
			name: "empty token",
			token: func(t *testing.T) string {
				return ""
			},
			wantErr: ErrUnauthorized,
		},
		{
			name: "missing required scope",
			token: func(t *testing.T) string {
				r := baseMintReq()
				r.Scope = []string{"owasp:gpt-4o"}
				return mustMint(t, privPEM, kid, r)
			},
			opts:    VerifierOptions{RequiredScope: []string{"soc2:gpt-4o"}},
			wantErr: ErrUnauthorized,
		},
		{
			name: "denylist store outage fails CLOSED",
			token: func(t *testing.T) string {
				return mustMint(t, privPEM, kid, baseMintReq())
			},
			denylist: func() *fakeDenylist {
				d := newFakeDenylist()
				d.callErr = errors.New("denylist store down")
				return d
			}(),
			wantErr: ErrRevocationUnavailable,
		},
		{
			name: "revocation store outage fails CLOSED",
			token: func(t *testing.T) string {
				return mustMint(t, privPEM, kid, baseMintReq())
			},
			revocation: func() *fakeRevocation {
				r := newFakeRevocation()
				r.callErr = errors.New("revocation store down")
				return r
			}(),
			wantErr: ErrRevocationUnavailable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.token(t)

			dl := tc.denylist
			if dl == nil {
				dl = newFakeDenylist()
			}
			rv := tc.revocation
			if rv == nil {
				rv = newFakeRevocation()
			}

			opts := tc.opts
			if opts.Now == nil {
				opts.Now = fixedClock(now.Add(1 * time.Second))
			}

			v, err := NewVerifier(map[string][]byte{kid: pubPEM}, dl, rv, opts)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}

			// The "jti revoked" case needs the actual minted jti in the set.
			if tc.name == "jti revoked (per-run kill)" {
				c, verr := decodeClaimsUnsafe(t, raw)
				if verr != nil {
					t.Fatalf("decode jti: %v", verr)
				}
				rv.mu.Lock()
				rv.revoked = map[string]bool{c.JTI: true}
				rv.mu.Unlock()
			}

			claims, err := v.Verify(raw)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Verify returned %v, want success", err)
				}
				if claims == nil {
					t.Fatal("Verify returned nil claims on success")
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Verify error = %v, want %v", err, tc.wantErr)
			}
			if claims != nil {
				t.Errorf("Verify returned non-nil claims (%+v) alongside error", claims)
			}
		})
	}
}

// N6/§11: a token body must never carry provider secrets, prompts, or tool-call
// content. A minted token's claims must contain only the specified fields.
func TestMintDoesNotLeakSecretsInClaims(t *testing.T) {
	privPEM, _ := genKeyPEM(t)
	tok := mustMint(t, privPEM, "kid-1", baseMintReq())
	payload := decodePayloadJSON(t, tok)
	forbidden := []string{"api_key", "apikey", "secret", "prompt", "messages", "tool_call", "password"}
	for _, f := range forbidden {
		if _, ok := payload[f]; ok {
			t.Errorf("token payload contains forbidden field %q", f)
		}
	}
}

// ---------------------------------------------------------------------------
// Denylist / Revocation behavioral contract (independent of JWT plumbing).
// ---------------------------------------------------------------------------

func TestDenylistAndRevocationSetSemantics(t *testing.T) {
	dl := newFakeDenylist()
	denied, err := dl.IsDenied("kid-x")
	if err != nil || denied {
		t.Fatalf("fresh denylist: denied=%v err=%v", denied, err)
	}
	if err := dl.Deny("kid-x"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if denied, _ := dl.IsDenied("kid-x"); !denied {
		t.Error("kid-x should be denied after Deny")
	}

	rv := newFakeRevocation()
	if revoked, _ := rv.IsRevoked("jti-1"); revoked {
		t.Error("fresh revocation should not report jti-1 revoked")
	}
	if err := rv.Revoke("jti-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if revoked, _ := rv.IsRevoked("jti-1"); !revoked {
		t.Error("jti-1 should be revoked after Revoke")
	}
}

// ---------------------------------------------------------------------------
// Low-level JWT test helpers (stdlib only). These deliberately do NOT depend
// on the package implementation so they can construct adversarial tokens.
// ---------------------------------------------------------------------------

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// splitJWT returns the three dot-separated segments or fails.
func splitJWT(t *testing.T, tok string) (hdr, payload, sig string) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a 3-part JWT: %q", tok)
	}
	return parts[0], parts[1], parts[2]
}

// decodePayloadJSON base64url-decodes the payload segment into a generic map.
func decodePayloadJSON(t *testing.T, tok string) map[string]any {
	t.Helper()
	_, payload, _ := splitJWT(t, tok)
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return m
}

// decodeClaimsUnsafe reads claims WITHOUT verifying the signature — used only
// to fetch the jti a token carries so the test can revoke it.
func decodeClaimsUnsafe(t *testing.T, tok string) (*Claims, error) {
	t.Helper()
	_, payload, _ := splitJWT(t, tok)
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// tamperTenant rewrites the tenant_id in the payload and re-assembles the token
// with the ORIGINAL signature — a tampered-but-old-sig token that must fail.
func tamperTenant(t *testing.T, tok, newTenant string) string {
	t.Helper()
	hdr, payload, sig := splitJWT(t, tok)
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	m["tenant_id"] = newTenant
	edited, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return hdr + "." + b64url(edited) + "." + sig
}

// forgeAlgNone builds an unsigned {"alg":"none"} token carrying valid-looking
// claims for kid — the classic downgrade attack. Verify must reject it.
func forgeAlgNone(t *testing.T, kid string, req MintRequest) string {
	t.Helper()
	hdr := map[string]any{"alg": "none", "typ": "JWT", "kid": kid}
	now := time.Now().Unix()
	payload := map[string]any{
		"sub":        req.RunID,
		"tenant_id":  req.TenantID,
		"scope":      req.Scope,
		"budget_ref": req.BudgetRef,
		"region":     req.Region,
		"iat":        now,
		"exp":        now + req.TTLSeconds,
		"jti":        "forged-jti",
		"kid":        kid,
	}
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(payload)
	return b64url(hb) + "." + b64url(pb) + "." // empty signature
}
