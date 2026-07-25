// Constructor seam for the real Minter/Verifier (feature 0064 §6).
//
// GREEN implementation: real ES256 (P-256) mint/verify using only Go stdlib
// crypto (crypto/ecdsa, crypto/x509, encoding/base64, encoding/json). No new
// dependency was needed — golang-jwt/jwt/v5 would not have materially
// simplified this narrow, single-alg (ES256) code path, and stdlib keeps the
// signature-forge / alg-none rejection logic explicit and auditable.
package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// defaultClockSkew is the §6 leeway applied to exp/iat when unset.
const defaultClockSkew = 30 * time.Second

// defaultMaxLifetime caps exp-iat (H3) when unset — defense-in-depth against a
// mint bug/compromise issuing an effectively immortal token.
const defaultMaxLifetime = 24 * time.Hour

// VerifierOptions tunes verify-time policy. Zero value is safe defaults:
// GREEN should treat a zero ClockSkew as the §6 default (30s) so callers
// that do not set it still get the specified leeway, and Now==nil as
// time.Now.
type VerifierOptions struct {
	// ClockSkew is the allowed leeway when checking exp/iat (§6: 30s).
	ClockSkew time.Duration
	// RequiredScope, when non-empty, must be a subset of the token scope.
	RequiredScope []string
	// MaxLifetime caps exp-iat as defense-in-depth (§6/H3; 0 ⇒ default 24h).
	MaxLifetime time.Duration
	// Now overrides the clock for deterministic tests (nil ⇒ time.Now).
	Now func() time.Time
}

// NewMinter builds the orchestrator-only Minter from a PEM-encoded EC
// (P-256 / ES256) private key and the kid advertised in minted headers.
func NewMinter(privateKeyPEM []byte, kid string) (Minter, error) {
	if kid == "" {
		return nil, fmt.Errorf("new minter: empty kid")
	}
	key, err := parseECPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("new minter: %w", err)
	}
	return &ecdsaMinter{key: key, kid: kid}, nil
}

// NewVerifier builds a broker-replica Verifier from a JWKS-style set of
// public keys (kid → PEM-encoded EC public key), plus the injected Denylist
// and Revocation seams. opts may be omitted for defaults.
func NewVerifier(publicKeysByKID map[string][]byte, denylist Denylist, revocation Revocation, opts ...VerifierOptions) (Verifier, error) {
	if denylist == nil || revocation == nil {
		return nil, fmt.Errorf("new verifier: denylist and revocation are required")
	}
	keys, err := parsePublicKeys(publicKeysByKID)
	if err != nil {
		return nil, fmt.Errorf("new verifier: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("new verifier: empty JWKS (no verify keys)")
	}
	return &ecdsaVerifier{
		keys:       keys,
		denylist:   denylist,
		revocation: revocation,
		opts:       resolveOptions(opts),
	}, nil
}

// resolveOptions applies §6 defaults to an optional options slice.
func resolveOptions(opts []VerifierOptions) VerifierOptions {
	o := VerifierOptions{}
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.ClockSkew <= 0 {
		o.ClockSkew = defaultClockSkew
	}
	if o.MaxLifetime <= 0 {
		o.MaxLifetime = defaultMaxLifetime
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// parsePublicKeys parses every PEM public key up front so verify stays O(1).
func parsePublicKeys(byKID map[string][]byte) (map[string]*ecdsa.PublicKey, error) {
	keys := make(map[string]*ecdsa.PublicKey, len(byKID))
	for kid, pemBytes := range byKID {
		pub, err := parseECPublicKey(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("kid %q: %w", kid, err)
		}
		keys[kid] = pub
	}
	return keys, nil
}

// parseECPrivateKey decodes a PKCS#8 PEM EC private key.
func parseECPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM: no block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an EC private key")
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("not a P-256 (ES256) key: %v", key.Curve.Params().Name)
	}
	return key, nil
}

// parseECPublicKey decodes a PKIX PEM EC public key.
func parseECPublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM: no block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkix: %w", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an EC public key")
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("not a P-256 (ES256) key: %v", key.Curve.Params().Name)
	}
	return key, nil
}
