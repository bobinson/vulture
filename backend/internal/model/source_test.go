package model

import (
	"strings"
	"testing"
)

func TestGitCredentials_Mask_NilReceiver(t *testing.T) {
	var c *GitCredentials
	result := c.Mask()
	if result != "(none)" {
		t.Fatalf("expected (none), got %q", result)
	}
}

func TestGitCredentials_Mask_Token(t *testing.T) {
	c := &GitCredentials{Type: "token", Value: "ghp_super_secret_token"}
	result := c.Mask()
	if strings.Contains(result, "ghp_super_secret_token") {
		t.Fatalf("Mask() leaked secret value: %s", result)
	}
	if !strings.Contains(result, "token") {
		t.Fatalf("Mask() should contain type: %s", result)
	}
	if !strings.Contains(result, "***") {
		t.Fatalf("Mask() should contain ***: %s", result)
	}
}

func TestGitCredentials_Mask_SSHKey(t *testing.T) {
	c := &GitCredentials{Type: "ssh_key", Value: "-----BEGIN OPENSSH PRIVATE KEY-----\nsecretbytes\n-----END OPENSSH PRIVATE KEY-----"}
	result := c.Mask()
	if strings.Contains(result, "BEGIN") {
		t.Fatalf("Mask() leaked PEM key: %s", result)
	}
	if strings.Contains(result, "secretbytes") {
		t.Fatalf("Mask() leaked key contents: %s", result)
	}
	if !strings.Contains(result, "ssh_key") {
		t.Fatalf("Mask() should contain type: %s", result)
	}
}
