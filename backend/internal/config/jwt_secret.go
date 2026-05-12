package config

import (
	"errors"
	"regexp"
	"strings"
)

// JWTSecretMinLen is the minimum acceptable length, in characters, for
// a JWT signing secret. 32 hex chars = 128 bits of entropy if drawn
// from a CSPRNG. Anything shorter is rejected at daemon startup. See
// plan invariant S1.
const JWTSecretMinLen = 32

// hexish allows hex characters, base64-alphabet characters, and
// hyphens (some CSPRNG outputs include `-`). The point is to require
// the secret to look like random output, not a phrase.
var hexish = regexp.MustCompile(`^[A-Za-z0-9_+/=\-]+$`)

// knownWeakSecrets is a deny-list of placeholder values that ship in
// example config files and tutorials. Catching these explicitly gives
// a clearer error than the entropy heuristic alone.
var knownWeakSecrets = map[string]struct{}{
	"change-me-in-production": {},
	"change-me":               {},
	"changeme":                {},
	"placeholder":             {},
	"dev-secret":              {},
	"secret":                  {},
	"password":                {},
	"insecure":                {},
	"test":                    {},
	"testing":                 {},
}

// ErrWeakJWTSecret is returned when the configured JWT secret fails
// the minimum-strength check. The error message is safe to print to
// stderr; it does not echo the secret itself.
var ErrWeakJWTSecret = errors.New(
	"VULTURE_JWT_SECRET is missing, too short, or a known placeholder " +
		"(minimum 32 random characters; generate with: openssl rand -hex 32)")

// ValidateJWTSecret returns nil iff s is acceptable as a signing
// secret in install mode. Local-dev mode ignores this and continues
// with whatever the user supplied — see caller in server.New().
func ValidateJWTSecret(s string) error {
	if len(s) < JWTSecretMinLen {
		return ErrWeakJWTSecret
	}
	if _, bad := knownWeakSecrets[strings.ToLower(s)]; bad {
		return ErrWeakJWTSecret
	}
	if !hexish.MatchString(s) {
		return ErrWeakJWTSecret
	}
	// Reject all-same-char strings ("aaaaaa..."). Heuristic for
	// "definitely not random".
	first := s[0]
	allSame := true
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			allSame = false
			break
		}
	}
	if allSame {
		return ErrWeakJWTSecret
	}
	return nil
}
