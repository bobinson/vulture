package cosign_test

// Tests for the cosign exec.Command wrapper.
//
// AC4 / AC6 / BLOCKER 1, 2 / MINOR 12:
//   - cosign.Verify(opts cosign.VerifyOptions) (cosign.VerifyResult, error)
//   - VULTURE_COSIGN_BINARY env var overrides which binary is run.
//   - Argv contract: cosign verify-blob --certificate-identity <id>
//       --certificate-oidc-issuer https://token.actions.githubusercontent.com
//       --bundle <bundle> <blob>
//   - Missing binary -> typed error with "cosign binary not found" message
//   - Non-zero exit -> typed error including stderr
//   - cosign version --short captured into VerifyResult.CosignVersion
//
// The mock cosign is a shell script written to t.TempDir(); each test
// sets VULTURE_COSIGN_BINARY to its path before calling.

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/cosign"
)

func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script mock cosign unsupported on Windows")
	}
}

// writeMockCosign writes an executable shell script at <dir>/cosign that
// records its argv (one per line) to <dir>/argv.log, prints `body` on
// stdout, prints `errBody` on stderr, and exits `code`. When invoked
// with `version --short` it instead prints `version` to stdout and
// exits 0 (so tests can assert the captured version).
func writeMockCosign(t *testing.T, dir, body, errBody, version string, code int) string {
	t.Helper()
	script := `#!/bin/sh
if [ "$1" = "version" ] && [ "$2" = "--short" ]; then
  echo "` + version + `"
  exit 0
fi
i=0
for a in "$@"; do
  i=$((i+1))
  echo "$a" >> "` + filepath.Join(dir, "argv.log") + `"
done
echo "` + body + `"
echo "` + errBody + `" >&2
exit ` + intToStr(code) + `
`
	p := filepath.Join(dir, "cosign")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("write mock cosign: %v", err)
	}
	return p
}

func intToStr(i int) string {
	switch i {
	case 0:
		return "0"
	case 1:
		return "1"
	case 2:
		return "2"
	}
	return "0"
}

func TestVerify_HappyPath_AC4(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	bin := writeMockCosign(t, dir, "verified", "", "v9.9.9-mock", 0)
	t.Setenv("VULTURE_COSIGN_BINARY", bin)

	blob := filepath.Join(dir, "plugin.toml")
	if err := os.WriteFile(blob, []byte("manifest"), 0o644); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	bundle := filepath.Join(dir, "plugin.toml.sigstore")
	if err := os.WriteFile(bundle, []byte("bundle"), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	res, err := cosign.Verify(cosign.VerifyOptions{
		BlobPath:           blob,
		BundlePath:         bundle,
		CertificateIdentity: "sigstore/returntocorp/vulture-plugin-semgrep",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.CosignVersion != "v9.9.9-mock" {
		t.Errorf("CosignVersion=%q, want v9.9.9-mock", res.CosignVersion)
	}
}

func TestVerify_ArgvContract_AC4(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	bin := writeMockCosign(t, dir, "verified", "", "v9.9.9-mock", 0)
	t.Setenv("VULTURE_COSIGN_BINARY", bin)

	blob := filepath.Join(dir, "plugin.toml")
	if err := os.WriteFile(blob, []byte("manifest"), 0o644); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	bundle := filepath.Join(dir, "plugin.toml.sigstore")
	if err := os.WriteFile(bundle, []byte("bundle"), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	_, err := cosign.Verify(cosign.VerifyOptions{
		BlobPath:           blob,
		BundlePath:         bundle,
		CertificateIdentity: "sigstore/foo/bar",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	argvLog, err := os.ReadFile(filepath.Join(dir, "argv.log"))
	if err != nil {
		t.Fatalf("argv log: %v", err)
	}
	got := strings.Split(strings.TrimSpace(string(argvLog)), "\n")
	want := []string{
		"verify-blob",
		"--certificate-identity",
		"sigstore/foo/bar",
		"--certificate-oidc-issuer",
		"https://token.actions.githubusercontent.com",
		"--bundle",
		bundle,
		blob,
	}
	if len(got) != len(want) {
		t.Fatalf("argv len got=%d want=%d (got=%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("argv[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestVerify_CosignBinaryMissing_AC6(t *testing.T) {
	skipOnWindows(t)
	t.Setenv("VULTURE_COSIGN_BINARY", "/definitely/not/a/real/binary/cosign-xyz")
	dir := t.TempDir()
	blob := filepath.Join(dir, "p.toml")
	bundle := filepath.Join(dir, "p.toml.sigstore")
	_ = os.WriteFile(blob, []byte("x"), 0o644)
	_ = os.WriteFile(bundle, []byte("b"), 0o644)

	_, err := cosign.Verify(cosign.VerifyOptions{
		BlobPath:           blob,
		BundlePath:         bundle,
		CertificateIdentity: "x",
	})
	if err == nil {
		t.Fatalf("expected error for missing cosign binary")
	}
	// Test the typed sentinel.
	if !errors.Is(err, cosign.ErrCosignNotFound) {
		t.Errorf("expected ErrCosignNotFound, got %v", err)
	}
	if !strings.Contains(err.Error(), "cosign binary not found") {
		t.Errorf("error should mention 'cosign binary not found', got %q", err.Error())
	}
}

func TestVerify_NonZeroExit_AC5(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	bin := writeMockCosign(t, dir, "", "signature verification failed: bad signature", "v9.9.9-mock", 1)
	t.Setenv("VULTURE_COSIGN_BINARY", bin)

	blob := filepath.Join(dir, "p.toml")
	bundle := filepath.Join(dir, "p.toml.sigstore")
	_ = os.WriteFile(blob, []byte("x"), 0o644)
	_ = os.WriteFile(bundle, []byte("b"), 0o644)

	_, err := cosign.Verify(cosign.VerifyOptions{
		BlobPath:           blob,
		BundlePath:         bundle,
		CertificateIdentity: "x",
	})
	if err == nil {
		t.Fatalf("expected non-nil error on cosign exit 1")
	}
	if !errors.Is(err, cosign.ErrVerifyFailed) {
		t.Errorf("expected ErrVerifyFailed sentinel, got %v", err)
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("error should include stderr, got %q", err.Error())
	}
}

func TestVerify_EnvVarOverridesDefaultBinary(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	bin := writeMockCosign(t, dir, "verified", "", "v0.0.0-stub", 0)
	t.Setenv("VULTURE_COSIGN_BINARY", bin)

	blob := filepath.Join(dir, "p.toml")
	bundle := filepath.Join(dir, "p.toml.sigstore")
	_ = os.WriteFile(blob, []byte("x"), 0o644)
	_ = os.WriteFile(bundle, []byte("b"), 0o644)

	res, err := cosign.Verify(cosign.VerifyOptions{
		BlobPath:           blob,
		BundlePath:         bundle,
		CertificateIdentity: "id",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.CosignVersion != "v0.0.0-stub" {
		t.Errorf("env var didn't override; got version %q", res.CosignVersion)
	}
}

func TestVerify_VersionUnknownOnFailure_MINOR12(t *testing.T) {
	skipOnWindows(t)
	// A version subcommand that fails should leave CosignVersion ==
	// "unknown" in the result, per LLD MINOR 12 + AC4.
	dir := t.TempDir()
	// Mock that fails version --short but succeeds verify-blob.
	script := `#!/bin/sh
if [ "$1" = "version" ]; then
  exit 1
fi
exit 0
`
	bin := filepath.Join(dir, "cosign")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("mock: %v", err)
	}
	t.Setenv("VULTURE_COSIGN_BINARY", bin)

	blob := filepath.Join(dir, "p.toml")
	bundle := filepath.Join(dir, "p.toml.sigstore")
	_ = os.WriteFile(blob, []byte("x"), 0o644)
	_ = os.WriteFile(bundle, []byte("b"), 0o644)

	res, err := cosign.Verify(cosign.VerifyOptions{
		BlobPath:           blob,
		BundlePath:         bundle,
		CertificateIdentity: "id",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.CosignVersion != "unknown" {
		t.Errorf("CosignVersion=%q, want \"unknown\"", res.CosignVersion)
	}
}
