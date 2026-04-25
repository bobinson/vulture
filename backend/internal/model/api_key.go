package model

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// APIKey is a bearer token for machine-to-machine auth.
type APIKey struct {
	ID         string     // uuid
	Prefix     string     // first 10 chars of key (e.g. "vk_abc123" — safe to display)
	Hash       string     // bcrypt hash of full key
	Name       string     // human label (e.g. "ci-github-actions")
	Scopes     []string   // ["read","write"]; future-proofing
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	CreatedBy  string // user ID that created it
}

// GenerateAPIKey returns (plaintext, bcrypt hash, error).
// The plaintext is shown ONCE to the creator; only the hash is persisted.
func GenerateAPIKey() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	key := "vk_" + base64.RawURLEncoding.EncodeToString(raw)
	h, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return key, string(h), nil
}

// VerifyAPIKey compares a presented key against a stored bcrypt hash.
func VerifyAPIKey(presented, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(presented)) == nil
}

// APIKeyPrefix extracts the first 10 characters. Used as a lookup index
// (stored unhashed) and for display in the UI without leaking the full key.
func APIKeyPrefix(key string) string {
	if len(key) < 10 {
		return key
	}
	return key[:10]
}
