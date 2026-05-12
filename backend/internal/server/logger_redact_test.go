package server

import (
	"strings"
	"testing"
)

func TestIsSensitiveFieldNameCaseInsensitive(t *testing.T) {
	if !IsSensitiveFieldName("AUTHORIZATION") {
		t.Error("AUTHORIZATION should match (case-insensitive)")
	}
	if !IsSensitiveFieldName("Authorization") {
		t.Error("Authorization should match")
	}
	if !IsSensitiveFieldName("OPENAI_API_KEY") {
		t.Error("OPENAI_API_KEY should match")
	}
	if !IsSensitiveFieldName("openai_api_key") {
		t.Error("openai_api_key should match")
	}
}

func TestIsSensitiveFieldNameNegative(t *testing.T) {
	notSensitive := []string{
		"fingerprint",
		"commit_sha",
		"file_path",
		"audit_id",
		"agent_type",
		"created_at",
		"severity",
		"category",
		"check_id",
	}
	for _, name := range notSensitive {
		if IsSensitiveFieldName(name) {
			t.Errorf("IsSensitiveFieldName(%q) = true; expected false (would over-redact)", name)
		}
	}
}

func TestMaskSecretShort(t *testing.T) {
	if got := MaskSecret("short"); got != "<redacted>" {
		t.Errorf("MaskSecret(short) = %q, want <redacted>", got)
	}
	if got := MaskSecret(""); got != "<redacted>" {
		t.Errorf("MaskSecret(empty) = %q, want <redacted>", got)
	}
}

func TestMaskSecretLong(t *testing.T) {
	secret := "sk_live_abcdef0123456789xyz"
	got := MaskSecret(secret)
	if !strings.HasPrefix(got, "sk_l") {
		t.Errorf("MaskSecret = %q, expected sk_l... prefix", got)
	}
	if !strings.HasSuffix(got, "9xyz") {
		t.Errorf("MaskSecret = %q, expected ...9xyz suffix", got)
	}
	if strings.Contains(got, "abcdef") {
		t.Errorf("MaskSecret = %q, leaked middle of secret", got)
	}
}

func TestRedactFieldSensitive(t *testing.T) {
	got := RedactField("Authorization", "Bearer sk-1234567890abcdef")
	if got == "Bearer sk-1234567890abcdef" {
		t.Errorf("RedactField did not redact sensitive value")
	}
	if !strings.Contains(got, "...") {
		t.Errorf("RedactField did not produce masked form: %q", got)
	}
}

func TestRedactFieldNonSensitive(t *testing.T) {
	// Critical: fingerprint values must pass through untouched.
	fp := "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	if got := RedactField("fingerprint", fp); got != fp {
		t.Errorf("RedactField over-redacted fingerprint: %q != %q", got, fp)
	}
	// Same for commit SHAs.
	sha := "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"
	if got := RedactField("commit_sha", sha); got != sha {
		t.Errorf("RedactField over-redacted commit_sha: %q != %q", got, sha)
	}
}

func TestRedactLineAuthHeader(t *testing.T) {
	got := RedactLine("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig")
	if strings.Contains(got, "payload") {
		t.Errorf("RedactLine leaked JWT body: %q", got)
	}
	if !strings.Contains(got, "Authorization: Bearer ") {
		t.Errorf("RedactLine removed the header name: %q", got)
	}
}

func TestRedactLineKVSecret(t *testing.T) {
	got := RedactLine("OPENAI_API_KEY=sk-1234567890abcdef0123 startup completed")
	if strings.Contains(got, "1234567890abcdef") {
		t.Errorf("RedactLine leaked OPENAI_API_KEY: %q", got)
	}
	if !strings.Contains(got, "OPENAI_API_KEY=") {
		t.Errorf("RedactLine removed the key prefix: %q", got)
	}
}

func TestRedactLinePreservesNonSecrets(t *testing.T) {
	original := "audit ec01e0218fba411103d1e2725182e976 completed, 131 findings"
	if got := RedactLine(original); got != original {
		t.Errorf("RedactLine over-redacted: %q != %q", got, original)
	}
}
