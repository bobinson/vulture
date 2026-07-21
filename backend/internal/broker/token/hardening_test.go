package token

// Post-audit hardening tests (feature 0064 §24). White-box: builds adversarial
// tokens with the package's own signing helpers so a valid signature isolates
// the policy/parse defect under test. Each asserts a defect the pre-fix code
// does NOT reject (real RED).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

// genKeyRaw returns a fresh P-256 key plus its PKIX public PEM (for the JWKS).
func genKeyRaw(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}

// genP384PEM returns a P-384 (wrong-curve) PKCS#8 private + PKIX public PEM.
func genP384PEM(t *testing.T) (privPEM, pubPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p384: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal p384 priv: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal p384 pub: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}

// signToken assembles a compact JWS with a valid signature over the given
// header+claims (white-box, so the signature is always correct — isolating the
// policy/parse check under test).
func signToken(t *testing.T, key *ecdsa.PrivateKey, hdr jwtHeader, c Claims) string {
	t.Helper()
	in, err := signingInput(hdr, c)
	if err != nil {
		t.Fatalf("signingInput: %v", err)
	}
	sig, err := signES256(key, in)
	if err != nil {
		t.Fatalf("signES256: %v", err)
	}
	return in + "." + b64(sig)
}

func newVerifierForKID(t *testing.T, kid string, pubPEM []byte, opts VerifierOptions) Verifier {
	t.Helper()
	v, err := NewVerifier(map[string][]byte{kid: pubPEM}, newFakeDenylist(), newFakeRevocation(), opts)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func validClaims(kid string, now int64) Claims {
	return Claims{
		Subject: "run-1", TenantID: "t1", Scope: []string{"scan:gpt-4o"},
		BudgetRef: "b", Region: "us", IssuedAt: now, ExpiresAt: now + 300, JTI: "jti-1", KID: kid,
	}
}

// C1 — header kid selects the key; payload kid evades the denylist. A token
// whose header.kid != payload.kid MUST be rejected (kill-switch bypass).
func TestVerify_RejectsKidHeaderPayloadMismatch(t *testing.T) {
	key, pubPEM := genKeyRaw(t)
	now := time.Unix(1_800_000_000, 0)
	c := validClaims("kid-evades", now.Unix()) // payload kid differs from header kid
	tok := signToken(t, key, jwtHeader{Alg: algES256, Typ: "JWT", KID: "kid-1"}, c)
	v := newVerifierForKID(t, "kid-1", pubPEM, VerifierOptions{Now: fixedClock(now.Add(time.Second))})
	if _, err := v.Verify(tok); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("kid mismatch: got %v, want ErrUnauthorized", err)
	}
}

// H2 — a token whose iat is in the future is not yet valid.
func TestVerify_RejectsFutureIat(t *testing.T) {
	key, pubPEM := genKeyRaw(t)
	now := time.Unix(1_800_000_000, 0)
	c := validClaims("kid-1", now.Unix())
	c.IssuedAt = now.Unix() + 3600 // 1h in the future
	c.ExpiresAt = c.IssuedAt + 300
	tok := signToken(t, key, jwtHeader{Alg: algES256, Typ: "JWT", KID: "kid-1"}, c)
	v := newVerifierForKID(t, "kid-1", pubPEM, VerifierOptions{Now: fixedClock(now)})
	if _, err := v.Verify(tok); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("future iat: got %v, want ErrTokenExpired", err)
	}
}

// H3 — a token whose lifetime exceeds the max is rejected (defense-in-depth).
func TestVerify_RejectsExcessiveLifetime(t *testing.T) {
	key, pubPEM := genKeyRaw(t)
	now := time.Unix(1_800_000_000, 0)
	c := validClaims("kid-1", now.Unix())
	c.ExpiresAt = c.IssuedAt + int64((25 * time.Hour).Seconds()) // > 24h default
	tok := signToken(t, key, jwtHeader{Alg: algES256, Typ: "JWT", KID: "kid-1"}, c)
	v := newVerifierForKID(t, "kid-1", pubPEM, VerifierOptions{Now: fixedClock(now.Add(time.Second))})
	if _, err := v.Verify(tok); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("excessive lifetime: got %v, want ErrTokenExpired", err)
	}
}

// M2 — a valid-but-oversized token (huge scope) is rejected before decode.
func TestVerify_RejectsOversizedToken(t *testing.T) {
	key, pubPEM := genKeyRaw(t)
	now := time.Unix(1_800_000_000, 0)
	c := validClaims("kid-1", now.Unix())
	c.Scope = []string{strings.Repeat("x", 9000)} // pushes the token past the cap
	tok := signToken(t, key, jwtHeader{Alg: algES256, Typ: "JWT", KID: "kid-1"}, c)
	v := newVerifierForKID(t, "kid-1", pubPEM, VerifierOptions{Now: fixedClock(now.Add(time.Second))})
	if _, err := v.Verify(tok); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("oversized token: got %v, want ErrUnauthorized", err)
	}
}

// C2 — non-P-256 keys are rejected at construction (never a mint-time panic).
func TestNewMinterVerifier_RejectNonP256(t *testing.T) {
	privPEM, pubPEM := genP384PEM(t)
	if _, err := NewMinter(privPEM, "kid-1"); err == nil {
		t.Fatal("NewMinter accepted a P-384 key; want error")
	}
	if _, err := NewVerifier(map[string][]byte{"kid-1": pubPEM}, newFakeDenylist(), newFakeRevocation()); err == nil {
		t.Fatal("NewVerifier accepted a P-384 key; want error")
	}
}

// H2 — mint rejects non-positive TTL (would produce an already-dead token).
func TestMint_RejectsNonPositiveTTL(t *testing.T) {
	privPEM, _ := genKeyPEM(t)
	m, err := NewMinter(privPEM, "kid-1")
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	for _, ttl := range []int64{0, -5} {
		r := baseMintReq()
		r.TTLSeconds = ttl
		if _, err := m.Mint(r); err == nil {
			t.Fatalf("Mint(TTL=%d) succeeded; want error", ttl)
		}
	}
}

// L2 — an empty JWKS is a construction error, not a silently-broken verifier.
func TestNewVerifier_RejectsEmptyJWKS(t *testing.T) {
	if _, err := NewVerifier(map[string][]byte{}, newFakeDenylist(), newFakeRevocation()); err == nil {
		t.Fatal("NewVerifier accepted an empty JWKS; want error")
	}
}

// M4 — signingInputOf must not panic on a dot-less string.
func TestSigningInputOf_NoDotNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("signingInputOf panicked: %v", r)
		}
	}()
	if got := signingInputOf("nodot"); got != "nodot" {
		t.Fatalf("signingInputOf(nodot) = %q, want %q", got, "nodot")
	}
}
