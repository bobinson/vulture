//go:build e2e

package e2e

// The default SSH host-key store reaches git through the server's data
// directory (0102 item 4, CWE-379/252). An ssh_key ingest on a server whose
// database file is <dir>/vulture_test.db hands git a GIT_SSH_COMMAND that
// pins UserKnownHostsFile to <dir>/ssh/known_hosts, created as a private
// directory of the backend's, and names a private key that exists while git
// runs and is gone once the ingest returns. A fake git first on PATH records
// what it was given and answers the clone, so nothing is dialled.

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// sshDefaultKeyArg extracts the key path from "ssh -i '<key>' ...".
var sshDefaultKeyArg = regexp.MustCompile(`^ssh -i '([^']+)' `)

func TestSourceIngest_SSHKeyClone_UsesDataDirHostKeyStore(t *testing.T) {
	tmp := sshStoreIsolate(t)
	t.Setenv("VULTURE_GIT_SSH_STRICT", "")
	rec := sshDefaultFakeGit(t)
	cfg := testConfig(t)
	dataDir := filepath.Dir(cfg.DBPath)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	resp, _, err := sshStorePost(addr)
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("an ssh_key ingest whose clone succeeds answered %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	store := filepath.Join(dataDir, "ssh", "known_hosts")
	cmd := sshDefaultRecord(t, rec, "ssh-command")
	sshDefaultWantStore(t, cmd, store)
	sshDefaultWantKeyGone(t, cmd, rec, tmp, dataDir)
}

// sshDefaultFakeGit puts a fake git first on PATH. For a clone it records
// GIT_SSH_COMMAND and whether the key it names holds anything, then creates
// the destination with one file and exits 0; any other git call (the
// metadata probes after the clone) exits 1, as outside a repository.
// Returns the directory it records into.
func sshDefaultFakeGit(t *testing.T) string {
	t.Helper()
	rec, bin := t.TempDir(), t.TempDir()
	script := `#!/bin/sh
case " $* " in *" clone "*) ;; *) exit 1 ;; esac
for dest; do :; done
printf '%s' "$GIT_SSH_COMMAND" > '` + rec + `/ssh-command'
key=${GIT_SSH_COMMAND#"ssh -i '"}
key=${key%%"'"*}
if [ -s "$key" ]; then printf present > '` + rec + `/key-at-clone'; fi
mkdir -p "$dest" && printf 'package main\n' > "$dest/main.go"
`
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o700); err != nil {
		t.Fatalf("write the fake git: %v", err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return rec
}

// sshDefaultWantStore: git was given the default host-key options naming
// store, and the store's directory is a private directory of ours.
func sshDefaultWantStore(t *testing.T, cmd, store string) {
	t.Helper()
	want := " -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile='" + store + "'"
	if !strings.HasSuffix(cmd, want) {
		t.Errorf("git was given GIT_SSH_COMMAND=%q, want it to end with %q", cmd, want)
	}
	sshDefaultWantPrivateDir(t, filepath.Dir(store))
}

func sshDefaultWantPrivateDir(t *testing.T, dir string) {
	t.Helper()
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("%s must be a directory with mode 0700: %v, %v", dir, fi, err)
	}
}

// sshDefaultWantKeyGone: the key cmd names held the key while git ran, and
// once the ingest returned it is gone and no file under tmp or roots holds
// the key.
func sshDefaultWantKeyGone(t *testing.T, cmd, rec, tmp string, roots ...string) {
	t.Helper()
	key := sshDefaultKeyPath(t, cmd, tmp)
	if sshDefaultRecord(t, rec, "key-at-clone") != "present" {
		t.Errorf("the key file %s was absent or empty while git ran", key)
	}
	if _, err := os.Lstat(key); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the key file %s must be removed once the ingest returns: lstat: %v", key, err)
	}
	sshDefaultWantNoKey(t, append(roots, tmp)...)
}

// sshDefaultKeyPath is the key file cmd names, which must lie directly under
// tmp (where the server writes it).
func sshDefaultKeyPath(t *testing.T, cmd, tmp string) string {
	t.Helper()
	m := sshDefaultKeyArg.FindStringSubmatch(cmd)
	if m == nil || filepath.Dir(m[1]) != tmp {
		t.Fatalf("git was given GIT_SSH_COMMAND=%q, want ssh -i '<key directly under %s>' ...", cmd, tmp)
	}
	return m[1]
}

// sshDefaultWantNoKey: no file under roots holds the private key.
func sshDefaultWantNoKey(t *testing.T, roots ...string) {
	t.Helper()
	for _, p := range sshStoreFilesHolding(sshStoreKey, roots...) {
		t.Errorf("the private key is still on disk at %s", p)
	}
}

// sshDefaultRecord is what the fake git recorded under name in rec ("" when
// it recorded nothing).
func sshDefaultRecord(t *testing.T, rec, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(rec, name))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("read the fake git's %s: %v", name, err)
	}
	return string(b)
}
