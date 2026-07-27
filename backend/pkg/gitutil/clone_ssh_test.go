package gitutil

import (
	"strings"
	"testing"
)

// TestBuildSSHCommand_DefaultVerifiesHostKey is the 0065 §1.3 red baseline for
// F8: by default buildSSHCommand must NOT disable host-key verification, i.e.
// it must contain neither StrictHostKeyChecking=no nor UserKnownHostsFile set
// to /dev/null. References buildSSHCommand, which does not yet exist —
// compile failure is the intended red state.
func TestBuildSSHCommand_DefaultVerifiesHostKey(t *testing.T) {
	out := buildSSHCommand("/tmp/vulture-ssh/key")
	if strings.Contains(out, "StrictHostKeyChecking=no") {
		t.Errorf("default must not disable host-key checking, got %q", out)
	}
	if strings.Contains(out, "/dev/null") {
		t.Errorf("default must not throw away known_hosts (/dev/null), got %q", out)
	}
}

// TestBuildSSHCommand_InsecureFlagRestoresLegacy verifies the documented
// rollback escape hatch: VULTURE_GIT_SSH_INSECURE=true restores the legacy
// no-verification string.
func TestBuildSSHCommand_InsecureFlagRestoresLegacy(t *testing.T) {
	t.Setenv("VULTURE_GIT_SSH_INSECURE", "true")
	out := buildSSHCommand("/tmp/vulture-ssh/key")
	if !strings.Contains(out, "StrictHostKeyChecking=no") {
		t.Errorf("insecure flag must restore StrictHostKeyChecking=no, got %q", out)
	}
	if !strings.Contains(out, "UserKnownHostsFile=/dev/null") {
		t.Errorf("insecure flag must restore UserKnownHostsFile=/dev/null, got %q", out)
	}
}

// TestBuildSSHCommand_QuotesPaths verifies §L1: the key path is single-quoted
// so a path containing spaces survives shell execution of GIT_SSH_COMMAND.
func TestBuildSSHCommand_QuotesPaths(t *testing.T) {
	out := buildSSHCommand("/tmp/vulture ssh/key")
	if !strings.Contains(out, "'/tmp/vulture ssh/key'") {
		t.Errorf("key path must be single-quoted, got %q", out)
	}
}
