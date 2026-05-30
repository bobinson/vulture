// Package cosign is a thin os/exec wrapper over the cosign CLI.
//
// Feature 0051 D1: rather than pull in the sigstore Go modules, we
// shell out to `cosign` so the operator's own (presumably current)
// cosign binary handles verification. Tests inject a stub binary via
// VULTURE_COSIGN_BINARY.
package cosign

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// OIDCIssuer is the GitHub Actions OIDC issuer URL.
//
// LLD "Cosign argv contract": v1 fixes the issuer to GitHub Actions —
// the only one Vulture community plugins are expected to use. A
// manifest signed via a different issuer must be installed as
// tier=user-supplied.
const OIDCIssuer = "https://token.actions.githubusercontent.com"

// VerifyOptions configures a single cosign verify-blob invocation.
type VerifyOptions struct {
	BlobPath            string
	BundlePath          string
	CertificateIdentity string
	OIDCIssuer          string
	CosignBinary        string
}

// VerifyResult captures observable side effects from cosign.
type VerifyResult struct {
	CosignVersion string
	Stdout        string
	Stderr        string
}

// Sentinel errors. Callers check via errors.Is.
var (
	ErrCosignNotFound = errors.New("cosign binary not found")
	ErrVerifyFailed   = errors.New("cosign verify failed")
)

// Verify runs `cosign verify-blob` against the supplied blob + bundle.
// Returns ErrCosignNotFound when the binary cannot be located and
// ErrVerifyFailed wrapped with stderr context on non-zero exit.
func Verify(opts VerifyOptions) (VerifyResult, error) {
	binary, err := resolveBinary(opts.CosignBinary)
	if err != nil {
		return VerifyResult{}, err
	}
	issuer := opts.OIDCIssuer
	if issuer == "" {
		issuer = OIDCIssuer
	}
	argv := []string{
		"verify-blob",
		"--certificate-identity", opts.CertificateIdentity,
		"--certificate-oidc-issuer", issuer,
		"--bundle", opts.BundlePath,
		opts.BlobPath,
	}
	stdout, stderr, runErr := runCommand(binary, argv)
	res := VerifyResult{
		CosignVersion: detectVersion(binary),
		Stdout:        stdout,
		Stderr:        stderr,
	}
	if runErr != nil {
		return res, fmt.Errorf("%w: %s", ErrVerifyFailed, strings.TrimSpace(stderr))
	}
	return res, nil
}

// resolveBinary picks the cosign binary: explicit field > env var > PATH.
func resolveBinary(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("%w: %s", ErrCosignNotFound, explicit)
		}
		return explicit, nil
	}
	if env := os.Getenv("VULTURE_COSIGN_BINARY"); env != "" {
		if _, err := os.Stat(env); err != nil {
			return "", fmt.Errorf("%w: %s", ErrCosignNotFound, env)
		}
		return env, nil
	}
	p, err := exec.LookPath("cosign")
	if err != nil {
		return "", fmt.Errorf("%w: not on PATH (set VULTURE_COSIGN_BINARY or install cosign)", ErrCosignNotFound)
	}
	return p, nil
}

// runCommand executes argv against binary and returns captured streams.
func runCommand(binary string, argv []string) (string, string, error) {
	cmd := exec.Command(binary, argv...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

// detectVersion shells out to `cosign version --short`. Best-effort:
// any failure (binary missing the subcommand, exit non-zero) yields
// "unknown" — MINOR 12.
func detectVersion(binary string) string {
	cmd := exec.Command(binary, "version", "--short")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &bytes.Buffer{}
	if err := cmd.Run(); err != nil {
		return "unknown"
	}
	v := strings.TrimSpace(out.String())
	if v == "" {
		return "unknown"
	}
	return v
}
