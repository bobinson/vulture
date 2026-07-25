// ES256 mint/verify plumbing (feature 0064 §6), stdlib crypto only.
//
// Wire format is a standard compact JWS: base64url(header).base64url(payload).
// base64url(signature), where signature is the JWS-canonical r||s (each padded
// to 32 bytes for P-256). Only alg=ES256 is accepted on verify; alg=none and
// any other alg are rejected as ErrUnauthorized (downgrade defence).
package token

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
)

// nowUnix is the mint-time clock seam (default: real wall clock). It is a
// package var so deterministic tests can pin mint time to match a fixed
// verifier clock; production always uses time.Now.
var nowUnix = func() int64 { return time.Now().Unix() }

const (
	algES256 = "ES256"
	// p256SigHalf is the byte width of each of r/s for a P-256 signature.
	p256SigHalf = 32
	// maxTokenBytes caps the raw token length before any decode (M2, DoS): a
	// per-run JWT is ~1 KB; anything far larger is rejected outright.
	maxTokenBytes = 8192
	// maxMintTTLSeconds bounds a minted token's lifetime (H2/H3): rejects
	// non-positive and overflow-prone TTLs at the source. 24h.
	maxMintTTLSeconds = int64(24 * 60 * 60)
)

// jwtHeader is the minted JWS header.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	KID string `json:"kid"`
}

// ecdsaMinter signs per-run tokens with the orchestrator private key.
type ecdsaMinter struct {
	key *ecdsa.PrivateKey
	kid string
}

// Mint issues a signed ES256 token for req. Each call gets a fresh jti.
func (m *ecdsaMinter) Mint(req MintRequest) (string, error) {
	if req.TTLSeconds <= 0 || req.TTLSeconds > maxMintTTLSeconds {
		return "", fmt.Errorf("mint: TTLSeconds must be in (0, %d]", maxMintTTLSeconds)
	}
	now := nowUnix()
	claims := Claims{
		Subject:   req.RunID,
		TenantID:  req.TenantID,
		Scope:     req.Scope,
		BudgetRef: req.BudgetRef,
		Region:    req.Region,
		IssuedAt:  now,
		ExpiresAt: now + req.TTLSeconds,
		JTI:       uuid.NewString(),
		KID:       m.kid,
	}
	signingInput, err := signingInput(jwtHeader{Alg: algES256, Typ: "JWT", KID: m.kid}, claims)
	if err != nil {
		return "", fmt.Errorf("mint: %w", err)
	}
	sig, err := signES256(m.key, signingInput)
	if err != nil {
		return "", fmt.Errorf("mint: %w", err)
	}
	return signingInput + "." + b64(sig), nil
}

// ecdsaVerifier validates tokens against the public JWKS + kill seams.
type ecdsaVerifier struct {
	keys       map[string]*ecdsa.PublicKey
	denylist   Denylist
	revocation Revocation
	opts       VerifierOptions
}

// Verify runs the full §6 admission check, returning claims or a sentinel.
func (v *ecdsaVerifier) Verify(raw string) (*Claims, error) {
	if len(raw) > maxTokenBytes {
		return nil, fmt.Errorf("verify: token too large: %w", ErrUnauthorized)
	}
	claims, err := v.authenticate(raw)
	if err != nil {
		return nil, err
	}
	if err := v.checkKillSeams(claims); err != nil {
		return nil, err
	}
	if err := v.checkPolicy(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// authenticate verifies the signature and returns the parsed claims.
func (v *ecdsaVerifier) authenticate(raw string) (*Claims, error) {
	header, payload, sig, err := splitToken(raw)
	if err != nil {
		return nil, err
	}
	if err := v.verifySignature(header, raw, sig); err != nil {
		return nil, err
	}
	claims, err := decodeClaims(payload)
	if err != nil {
		return nil, err
	}
	// C1: the header kid selects the verify key, so the payload kid (which the
	// denylist checks) MUST equal it — otherwise a stolen, denylisted key could
	// set a trusted header kid and an unlisted payload kid to evade the kill switch.
	if header.KID != claims.KID {
		return nil, fmt.Errorf("verify: kid header/payload mismatch: %w", ErrUnauthorized)
	}
	return claims, nil
}

// verifySignature enforces alg=ES256, selects the JWKS key by kid, and checks
// the signature. Every failure maps to ErrUnauthorized (no oracle detail).
func (v *ecdsaVerifier) verifySignature(header jwtHeader, raw string, sig []byte) error {
	if header.Alg != algES256 {
		return fmt.Errorf("verify: alg %q not accepted: %w", header.Alg, ErrUnauthorized)
	}
	key, ok := v.keys[header.KID]
	if !ok {
		return fmt.Errorf("verify: unknown kid: %w", ErrUnauthorized)
	}
	if err := verifyES256(key, signingInputOf(raw), sig); err != nil {
		return fmt.Errorf("verify: %w", ErrUnauthorized)
	}
	return nil
}

// checkKillSeams enforces the kid denylist then the jti revocation set,
// failing CLOSED (ErrRevocationUnavailable) when either store is unavailable.
func (v *ecdsaVerifier) checkKillSeams(c *Claims) error {
	if err := v.checkKidDenied(c.KID); err != nil {
		return err
	}
	return v.checkJTIRevoked(c.JTI)
}

// checkKidDenied fails CLOSED on denylist-store outage; ErrKidDenied when hit.
func (v *ecdsaVerifier) checkKidDenied(kid string) error {
	denied, err := v.denylist.IsDenied(kid)
	if err != nil {
		return fmt.Errorf("verify: denylist: %w", ErrRevocationUnavailable)
	}
	if denied {
		return fmt.Errorf("verify: %w", ErrKidDenied)
	}
	return nil
}

// checkJTIRevoked fails CLOSED on revocation-store outage; ErrTokenRevoked hit.
func (v *ecdsaVerifier) checkJTIRevoked(jti string) error {
	revoked, err := v.revocation.IsRevoked(jti)
	if err != nil {
		return fmt.Errorf("verify: revocation: %w", ErrRevocationUnavailable)
	}
	if revoked {
		return fmt.Errorf("verify: %w", ErrTokenRevoked)
	}
	return nil
}

// checkPolicy enforces temporal validity then required scope.
func (v *ecdsaVerifier) checkPolicy(c *Claims) error {
	if err := v.checkTemporal(c); err != nil {
		return err
	}
	if !scopeSatisfied(c.Scope, v.opts.RequiredScope) {
		return fmt.Errorf("verify: missing required scope: %w", ErrUnauthorized)
	}
	return nil
}

// checkTemporal enforces not-yet-valid (future iat, H2), expiry (exp is
// EXCLUSIVE per RFC 7519, M5), and the max token lifetime (H3) — all with the
// configured clock skew. All map to ErrTokenExpired (temporal invalidity).
func (v *ecdsaVerifier) checkTemporal(c *Claims) error {
	now := v.opts.Now().Unix()
	skew := int64(v.opts.ClockSkew.Seconds())
	switch {
	case now+skew < c.IssuedAt:
		return fmt.Errorf("verify: not yet valid: %w", ErrTokenExpired)
	case now >= c.ExpiresAt+skew:
		return fmt.Errorf("verify: %w", ErrTokenExpired)
	case v.exceedsMaxLifetime(c):
		return fmt.Errorf("verify: lifetime exceeds max: %w", ErrTokenExpired)
	}
	return nil
}

// exceedsMaxLifetime reports whether exp-iat is over the configured cap (0=off).
func (v *ecdsaVerifier) exceedsMaxLifetime(c *Claims) bool {
	max := int64(v.opts.MaxLifetime.Seconds())
	return max > 0 && c.ExpiresAt-c.IssuedAt > max
}

// scopeSatisfied reports whether required is a subset of granted.
func scopeSatisfied(granted, required []string) bool {
	if len(required) == 0 {
		return true
	}
	set := toSet(granted)
	for _, r := range required {
		if _, ok := set[r]; !ok {
			return false
		}
	}
	return true
}

// toSet builds a membership set from a slice (O(n) build, O(1) lookup).
func toSet(vals []string) map[string]struct{} {
	set := make(map[string]struct{}, len(vals))
	for _, v := range vals {
		set[v] = struct{}{}
	}
	return set
}

// --- JWT wire helpers (stdlib only) ---

// splitToken splits a compact JWS into its decoded header, raw payload, and
// decoded signature. Any structural defect maps to ErrUnauthorized.
func splitToken(raw string) (jwtHeader, string, []byte, error) {
	parts, err := jwsParts(raw)
	if err != nil {
		return jwtHeader{}, "", nil, err
	}
	h, err := parseHeader(parts[0])
	if err != nil {
		return jwtHeader{}, "", nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return jwtHeader{}, "", nil, fmt.Errorf("verify: bad signature: %w", ErrUnauthorized)
	}
	return h, parts[1], sig, nil
}

// jwsParts splits a compact JWS into exactly 3 non-empty header/payload
// segments (signature may be empty so alg=none is caught later by alg check).
func jwsParts(raw string) ([]string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("verify: malformed token: %w", ErrUnauthorized)
	}
	return parts, nil
}

// parseHeader base64url-decodes and unmarshals the JWS header segment.
func parseHeader(seg string) (jwtHeader, error) {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return jwtHeader{}, fmt.Errorf("verify: bad header: %w", ErrUnauthorized)
	}
	var h jwtHeader
	if err := json.Unmarshal(raw, &h); err != nil {
		return jwtHeader{}, fmt.Errorf("verify: bad header json: %w", ErrUnauthorized)
	}
	return h, nil
}

// signingInputOf returns the header.payload prefix that was signed.
func signingInputOf(raw string) string {
	i := strings.LastIndexByte(raw, '.')
	if i < 0 {
		return raw
	}
	return raw[:i]
}

// decodeClaims base64url-decodes and unmarshals the payload segment.
func decodeClaims(payload string) (*Claims, error) {
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("verify: bad payload: %w", ErrUnauthorized)
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("verify: bad payload json: %w", ErrUnauthorized)
	}
	return &c, nil
}

// signingInput builds base64url(header).base64url(payload).
func signingInput(h jwtHeader, c Claims) (string, error) {
	hb, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	pb, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	return b64([]byte(hb)) + "." + b64(pb), nil
}

// signES256 signs input with the P-256 key, returning JWS r||s bytes.
func signES256(key *ecdsa.PrivateKey, input string) ([]byte, error) {
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign: %w", err)
	}
	// Belt-and-suspenders (C2): FillBytes into a 32-byte buffer panics if r/s
	// exceed 32 bytes (a non-P-256 key). Curve is validated at construction, but
	// never let a slipped-through key panic the minter — return an error instead.
	if r.BitLen() > 8*p256SigHalf || s.BitLen() > 8*p256SigHalf {
		return nil, errors.New("ecdsa sign: non-P-256 signature scalar")
	}
	out := make([]byte, 2*p256SigHalf)
	r.FillBytes(out[:p256SigHalf])
	s.FillBytes(out[p256SigHalf:])
	return out, nil
}

// verifyES256 checks a JWS r||s signature over input against key.
func verifyES256(key *ecdsa.PublicKey, input string, sig []byte) error {
	if len(sig) != 2*p256SigHalf {
		return errors.New("bad signature length")
	}
	digest := sha256.Sum256([]byte(input))
	r := new(big.Int).SetBytes(sig[:p256SigHalf])
	s := new(big.Int).SetBytes(sig[p256SigHalf:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return errors.New("signature mismatch")
	}
	return nil
}

// b64 is base64url without padding (JWS canonical).
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
