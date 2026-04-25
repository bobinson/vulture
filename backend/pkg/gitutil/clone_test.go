package gitutil

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

func TestCloneInvalidURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := Clone(ctx, "https://invalid.example.com/nonexistent/repo.git", t.TempDir(), 1, nil)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestCloneCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Clone(ctx, "https://github.com/octocat/Hello-World.git", t.TempDir(), 1, nil)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestEmbedToken_EmbedsCorrectly(t *testing.T) {
	out, err := embedToken("https://github.com/org/repo.git", "ghp_abc123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "x-access-token:ghp_abc123@") {
		t.Fatalf("token not embedded: %s", out)
	}
}

func TestEmbedToken_RejectsNonHTTP(t *testing.T) {
	_, err := embedToken("git@github.com:org/repo.git", "tok")
	if err == nil {
		t.Fatal("should reject non-http URL for token auth")
	}
}

func TestEmbedToken_PreservesPath(t *testing.T) {
	out, err := embedToken("https://github.com/org/repo.git", "tok123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out, "/org/repo.git") {
		t.Fatalf("path not preserved: %s", out)
	}
}

func TestScrubCredentials_RemovesTokenFromMessage(t *testing.T) {
	err := fmt.Errorf("failed: https://x-access-token:secret123@github.com/org/repo.git")
	scrubbed := scrubCredentials(err).Error()
	if strings.Contains(scrubbed, "secret123") {
		t.Fatalf("scrubbed still contains secret: %s", scrubbed)
	}
	if !strings.Contains(scrubbed, "[REDACTED]") {
		t.Fatalf("expected REDACTED marker: %s", scrubbed)
	}
}

func TestScrubCredentials_NilError(t *testing.T) {
	if scrubCredentials(nil) != nil {
		t.Fatal("expected nil for nil input")
	}
}

func TestScrubCredentials_NoCredsInMessage(t *testing.T) {
	err := fmt.Errorf("plain error, no urls")
	scrubbed := scrubCredentials(err).Error()
	if scrubbed != "plain error, no urls" {
		t.Fatalf("unexpected change: %s", scrubbed)
	}
}

func TestWriteSSHKey_CreatesFile(t *testing.T) {
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n"
	path, cleanup, err := writeSSHKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if path == "" {
		t.Fatal("expected non-empty path")
	}
}

func TestValidateGitURL_HTTPSAllowed(t *testing.T) {
	if err := ValidateGitURL("https://github.com/org/repo.git", nil); err != nil {
		t.Fatalf("https should be allowed: %v", err)
	}
}

func TestValidateGitURL_ExtBlocked(t *testing.T) {
	if err := ValidateGitURL("ext::sh -c cmd", nil); err == nil {
		t.Fatal("ext:: should be blocked")
	}
}

func TestValidateGitURL_SSHShorthandBlocked(t *testing.T) {
	if err := ValidateGitURL("git@github.com:org/repo.git", nil); err == nil {
		t.Fatal("SSH shorthand should be blocked without ssh_key creds")
	}
}

func TestValidateGitURL_SSHShorthandAllowedWithKey(t *testing.T) {
	creds := &model.GitCredentials{Type: "ssh_key", Value: "pem"}
	if err := ValidateGitURL("git@github.com:org/repo.git", creds); err != nil {
		t.Fatalf("SSH shorthand should be allowed with ssh_key: %v", err)
	}
}

func TestValidateGitURL_SSHSchemeAllowedWithKey(t *testing.T) {
	creds := &model.GitCredentials{Type: "ssh_key", Value: "pem"}
	if err := ValidateGitURL("ssh://git@github.com/org/repo.git", creds); err != nil {
		t.Fatalf("ssh:// should be allowed with ssh_key: %v", err)
	}
}

func TestValidateGitURL_SSHSchemeBlockedWithoutKey(t *testing.T) {
	if err := ValidateGitURL("ssh://git@github.com/org/repo.git", nil); err == nil {
		t.Fatal("ssh:// should be blocked without ssh_key creds")
	}
}

func TestClone_NilCreds_BehavesAsOriginal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Nil creds should work the same as the original function
	err := Clone(ctx, "https://invalid.example.com/nonexistent/repo.git", t.TempDir(), 1, nil)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}
