//go:build e2e

package e2e

// CWE-379/252 (0102 item 4): a key-based git clone keeps its SSH host-key
// store at <directory of the database file>/ssh/known_hosts and verifies the
// store before anything is written. A store another account could have
// planted, here a symlink to a directory it controls, refuses the clone at
// once: a generic 500 whose cause and remedy reach only the server log,
// nothing written through the link, and the private key never on disk.

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const (
	// sshStoreURL is TEST-NET-1 (RFC 5737): public to the SSRF guard, so the
	// clone is allowed, and never answered, so a clone that dials hangs.
	sshStoreURL = "ssh://git@192.0.2.1/acme/repo.git"
	// sshStoreKey stands in for a private key; only its bytes are looked for.
	sshStoreKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nitem4-e2e-key-material\n-----END OPENSSH PRIVATE KEY-----\n"

	sshStoreClientTimeout = 15 * time.Second
	sshStoreMaxLatency    = 5 * time.Second
)

func TestSourceIngest_SSHKeyClone_RefusesPlantedHostKeyStore(t *testing.T) {
	tmp := sshStoreIsolate(t)
	cfg := testConfig(t)
	dataDir := filepath.Dir(cfg.DBPath)
	attacker := sshStorePlant(t, dataDir)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()
	logs := errBodyCaptureLog(t)

	resp, elapsed, err := sshStorePost(addr)
	sshStoreWantNoTrace(t, attacker, tmp, dataDir)
	if err != nil {
		t.Fatalf("POST /api/sources gave no answer within %s: the clone dialled instead of refusing the planted store: %v", sshStoreClientTimeout, err)
	}
	if elapsed >= sshStoreMaxLatency {
		t.Errorf("the refusal took %s, want under %s: a refused store must not dial", elapsed, sshStoreMaxLatency)
	}
	id := errBodyWantInternal(t, resp, "symlink", "known_hosts", "VULTURE_", dataDir, attacker)
	line := errBodyWantOneCauseLine(t, logs, id, "symlink")
	errBodyWantAll(t, "the log line for "+id, line, "VULTURE_GIT_SSH_KNOWN_HOSTS", filepath.Join(dataDir, "ssh"))
}

// sshStoreIsolate points TMPDIR (where a key file and the clone go) at a
// directory of this test's own, clears the settings that would bypass the
// store or refuse the host for another reason, keeps the server off the
// host's docker and shared staging directory, and kills whatever a dialling
// clone leaves running under TMPDIR once the test ends. Returns that TMPDIR.
func sshStoreIsolate(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	for name, value := range map[string]string{
		"TMPDIR":                        tmp,
		"VULTURE_GIT_SSH_KNOWN_HOSTS":   "",
		"VULTURE_GIT_SSH_INSECURE":      "",
		"VULTURE_GIT_HOST_ALLOWLIST":    "",
		"VULTURE_DISABLE_SUPERVISOR":    "true",
		"VULTURE_SUPERVISOR_AUDITS_DIR": filepath.Join(tmp, "audit-inputs"),
	} {
		t.Setenv(name, value)
	}
	t.Cleanup(func() { sshStoreKillUnder(tmp) })
	return tmp
}

// sshStorePlant makes the data directory private, so the planted link is the
// only thing wrong with the store, and plants <dataDir>/ssh as a symlink to a
// directory an attacker controls. Returns that directory.
func sshStorePlant(t *testing.T, dataDir string) string {
	t.Helper()
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatalf("chmod data dir: %v", err)
	}
	attacker := t.TempDir()
	if err := os.Symlink(attacker, filepath.Join(dataDir, "ssh")); err != nil {
		t.Fatalf("plant the store link: %v", err)
	}
	return attacker
}

func sshStorePost(addr string) (*http.Response, time.Duration, error) {
	b, err := json.Marshal(map[string]interface{}{
		"type":            "git",
		"url":             sshStoreURL,
		"git_credentials": map[string]string{"type": "ssh_key", "value": sshStoreKey},
	})
	if err != nil {
		return nil, 0, err
	}
	client := &http.Client{Timeout: sshStoreClientTimeout}
	start := time.Now()
	resp, err := client.Post("http://"+addr+"/api/sources", "application/json", bytes.NewReader(b))
	return resp, time.Since(start), err
}

// sshStoreWantNoTrace: nothing was written through the planted link, and no
// file under roots holds the private key.
func sshStoreWantNoTrace(t *testing.T, attacker string, roots ...string) {
	t.Helper()
	if ents, err := os.ReadDir(attacker); err != nil || len(ents) != 0 {
		t.Errorf("the planted link's target must stay empty: entries %v, err %v", ents, err)
	}
	for _, p := range sshStoreFilesHolding(sshStoreKey, roots...) {
		t.Errorf("the private key reached disk and is still there: %s", p)
	}
}

func sshStoreFilesHolding(content string, roots ...string) []string {
	var hits []string
	visit := func(p string, d fs.DirEntry, err error) error {
		if err == nil && sshStoreRegularHolds(p, d, content) {
			hits = append(hits, p)
		}
		return nil
	}
	for _, root := range roots {
		_ = filepath.WalkDir(root, visit)
	}
	return hits
}

func sshStoreRegularHolds(path string, d fs.DirEntry, content string) bool {
	return d.Type().IsRegular() && sshStoreFileHolds(path, content)
}

func sshStoreFileHolds(path, content string) bool {
	b, err := os.ReadFile(path)
	return err == nil && bytes.Contains(b, []byte(content))
}

// sshStoreKillUnder kills every process whose command line names dir: the
// git and ssh of a clone that dialled (its key and clone paths live under the
// test's TMPDIR). Linux /proc only; elsewhere it finds nothing.
func sshStoreKillUnder(dir string) {
	cmdlines, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, f := range cmdlines {
		if sshStoreFileHolds(f, dir) {
			sshStoreKill(filepath.Base(filepath.Dir(f)))
		}
	}
}

func sshStoreKill(pid string) {
	n, err := strconv.Atoi(pid)
	if err != nil || n == os.Getpid() {
		return
	}
	if p, err := os.FindProcess(n); err == nil {
		_ = p.Kill()
	}
}
