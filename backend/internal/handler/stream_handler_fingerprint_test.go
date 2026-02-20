package handler

import "testing"

func TestGenerateFingerprint_Deterministic(t *testing.T) {
	fp1 := generateFingerprint("Missing Error Handling", "cmd/main.go", "error_handling", "chaos")
	fp2 := generateFingerprint("Missing Error Handling", "cmd/main.go", "error_handling", "chaos")
	if fp1 != fp2 {
		t.Errorf("fingerprints should be deterministic: %q != %q", fp1, fp2)
	}
}

func TestGenerateFingerprint_DifferentInputs(t *testing.T) {
	fp1 := generateFingerprint("Missing Error Handling", "cmd/main.go", "error_handling", "chaos")
	fp2 := generateFingerprint("SQL Injection", "cmd/main.go", "injection", "owasp")
	if fp1 == fp2 {
		t.Error("different findings should produce different fingerprints")
	}
}

func TestGenerateFingerprint_CaseInsensitive(t *testing.T) {
	fp1 := generateFingerprint("Missing Error Handling", "cmd/main.go", "error_handling", "chaos")
	fp2 := generateFingerprint("MISSING ERROR HANDLING", "cmd/main.go", "ERROR_HANDLING", "CHAOS")
	if fp1 != fp2 {
		t.Errorf("fingerprints should be case-insensitive on title/category/agent: %q != %q", fp1, fp2)
	}
}

func TestGenerateFingerprint_TrimSpaces(t *testing.T) {
	fp1 := generateFingerprint("Missing Error Handling", "cmd/main.go", "error_handling", "chaos")
	fp2 := generateFingerprint("  Missing Error Handling  ", "  cmd/main.go  ", "  error_handling  ", "  chaos  ")
	if fp1 != fp2 {
		t.Errorf("fingerprints should trim spaces: %q != %q", fp1, fp2)
	}
}

func TestGenerateFingerprint_Length(t *testing.T) {
	fp := generateFingerprint("test", "test.go", "cat", "agent")
	if len(fp) != 32 {
		t.Errorf("fingerprint should be 32 hex chars (16 bytes), got %d: %s", len(fp), fp)
	}
}
