package gitutil

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// 0036 Phase 3 (M15) — writeAskpassScript must:
//   * Place the token in a 0700 file (not argv, not env).
//   * Answer the "Username" prompt with x-access-token (GitHub convention).
//   * Answer any other prompt (typically "Password" or "Password for ...")
//     with the token itself.
//   * Be cleanly removed by the returned cleanup func.

func TestWriteAskpassScript_RespondsToUsername(t *testing.T) {
	path, cleanup, err := writeAskpassScript("ghp_secret123")
	if err != nil {
		t.Fatalf("writeAskpassScript: %v", err)
	}
	defer cleanup()

	out, err := exec.Command(path, "Username for 'https://github.com':").Output()
	if err != nil {
		t.Fatalf("askpass script run failed: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != "x-access-token" {
		t.Errorf("Username prompt got %q; want x-access-token", got)
	}
}

func TestWriteAskpassScript_RespondsWithToken(t *testing.T) {
	token := "ghp_my_secret_token_value"
	path, cleanup, err := writeAskpassScript(token)
	if err != nil {
		t.Fatalf("writeAskpassScript: %v", err)
	}
	defer cleanup()

	out, err := exec.Command(path, "Password for 'https://x-access-token@github.com':").Output()
	if err != nil {
		t.Fatalf("askpass script run failed: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != token {
		t.Errorf("Password prompt got %q; want %q", got, token)
	}
}

func TestWriteAskpassScript_FileIsRestricted(t *testing.T) {
	path, cleanup, err := writeAskpassScript("tok")
	if err != nil {
		t.Fatalf("writeAskpassScript: %v", err)
	}
	defer cleanup()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// 0700 — only the script's owner can read or execute. The token
	// is content of this file, so any laxer mode is a leak.
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Errorf("askpass script mode = %o; want 0700", mode)
	}
}

func TestWriteAskpassScript_CleanupRemovesFile(t *testing.T) {
	path, cleanup, err := writeAskpassScript("tok")
	if err != nil {
		t.Fatalf("writeAskpassScript: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("script should exist before cleanup: %v", err)
	}
	cleanup()
	if _, err := os.Stat(path); err == nil {
		t.Errorf("script still present after cleanup: %s", path)
	}
}
