package config

import (
	"strings"
	"testing"
)

func TestValidateJWTSecretAcceptsRandomHex(t *testing.T) {
	// 64 random hex chars (256 bits)
	good := "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	if err := ValidateJWTSecret(good); err != nil {
		t.Fatalf("ValidateJWTSecret(<random hex>) = %v, want nil", err)
	}
}

func TestValidateJWTSecretAcceptsBase64ish(t *testing.T) {
	// 32+ chars with base64 alphabet
	good := "abcdef0123456789ABCDEFGHIJKLMNOP_+/="
	if err := ValidateJWTSecret(good); err != nil {
		t.Fatalf("ValidateJWTSecret(<base64ish>) = %v, want nil", err)
	}
}

func TestValidateJWTSecretRejectsTooShort(t *testing.T) {
	if err := ValidateJWTSecret(strings.Repeat("x", 31)); err == nil {
		t.Fatal("ValidateJWTSecret(31-char) = nil, want error")
	}
	if err := ValidateJWTSecret(""); err == nil {
		t.Fatal("ValidateJWTSecret(empty) = nil, want error")
	}
}

func TestValidateJWTSecretRejectsPlaceholders(t *testing.T) {
	for _, p := range []string{
		"change-me-in-production",
		"CHANGE-ME-IN-PRODUCTION",
		"change-me",
		"changeme",
		"secret",
		"password",
		"placeholder",
		"insecure",
		"test",
	} {
		if err := ValidateJWTSecret(p); err == nil {
			t.Errorf("ValidateJWTSecret(%q) = nil, want error", p)
		}
	}
}

func TestValidateJWTSecretRejectsAllSameChar(t *testing.T) {
	// Long enough to pass length, but no entropy.
	bad := strings.Repeat("a", 64)
	if err := ValidateJWTSecret(bad); err == nil {
		t.Fatal("ValidateJWTSecret(all-same-char) = nil, want error")
	}
}

func TestValidateJWTSecretRejectsShellChars(t *testing.T) {
	// Long enough to pass length, but contains spaces / quotes —
	// these are unlikely in a CSPRNG-derived secret and probably
	// indicate a human-written placeholder.
	bad := "the quick brown fox jumps over the lazy dog xyz"
	if err := ValidateJWTSecret(bad); err == nil {
		t.Fatal("ValidateJWTSecret(<has spaces>) = nil, want error")
	}
}
