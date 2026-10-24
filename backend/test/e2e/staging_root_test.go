//go:build e2e

package e2e

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The plugin staging root (VULTURE_SUPERVISOR_AUDITS_DIR, default
// /tmp/vulture-audit-inputs) is bind-mounted into plugin containers. When it
// does not exist, Docker creates the mount source as root, and a non-root
// dev backend can then never stage an audit into it: every plugin is
// skipped with "mkdir …: permission denied" and the audit is marked failed.
// The backend must create the root itself, as its own user, at startup —
// before any plugin container is started.

func TestStagingRoot_CreatedAtStartupByTheBackendUser(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nested", "audit-inputs")
	t.Setenv("VULTURE_SUPERVISOR_AUDITS_DIR", root)

	_, cleanup := startTestServer(t, testConfig(t))
	defer cleanup()

	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("staging root was not created at startup: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("staging root %s is not a directory", root)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		t.Fatalf("staging root owned by uid %d, want the backend's uid %d", st.Uid, os.Getuid())
	}
	probe := filepath.Join(root, "audit-probe")
	if err := os.Mkdir(probe, 0o755); err != nil {
		t.Fatalf("backend cannot create an audit dir under the staging root: %v", err)
	}
}

func TestStagingRoot_UnwritableRootIsReportedAtStartup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	root := filepath.Join(t.TempDir(), "audit-inputs")
	if err := os.Mkdir(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
	t.Setenv("VULTURE_SUPERVISOR_AUDITS_DIR", root)

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	// The backend must still start: skills-only agents do not need staging.
	_, cleanup := startTestServer(t, testConfig(t))
	defer cleanup()

	out := buf.String()
	for _, want := range []string{root, "not writable", "VULTURE_SUPERVISOR_AUDITS_DIR"} {
		if !strings.Contains(out, want) {
			t.Fatalf("startup log does not report the unusable staging root (missing %q):\n%s", want, out)
		}
	}
}
