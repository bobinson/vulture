//go:build e2e

package e2e

// Folder browse policy (feature 0102, CWE-22).
//
// GET /api/filesystem/browse lists server directories, so outside local mode
// it follows the local-path policy that local ingest follows:
//   - centralized with no VULTURE_SOURCE_ROOT: refused before the path is
//     looked at, with one text for every path (no existence oracle);
//   - read-only: always refused, root or not;
//   - centralized with a root: confined to it, and every outside path gets
//     the same refusal, whatever it resolves to;
//   - only human writers (member, admin) may browse; viewers and API keys
//     have no browse consumer and are refused.
//
// Local mode keeps its behaviour.
//
// Mode-B fixtures use a dedicated root, t.TempDir()/root, and take outside
// paths from os.MkdirTemp: ciTestConfig's own root is the per-test parent of
// every t.TempDir(), so a sibling temp dir would count as inside it.

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

const (
	browseDisabledText = "local paths are disabled on this server: set VULTURE_SOURCE_ROOT to allow them in centralized mode"
	browseRoleText     = "requires member or admin role"
	browseOutsideText  = "access denied: path outside source root"
)

// browseReply is one browse response: its status, raw body and "error" text.
type browseReply struct {
	path   string
	status int
	body   string
	errMsg string
}

// browseAs GETs the browse endpoint for path, sending token as a Bearer
// credential when it is non-empty.
func browseAs(t *testing.T, addr, token, path string) browseReply {
	t.Helper()
	resp, err := httpGetWithAuth(addr, "/api/filesystem/browse?path="+url.QueryEscape(path), token)
	if err != nil {
		t.Fatalf("GET browse %q: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read browse %q: %v", path, err)
	}
	var parsed struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &parsed)
	return browseReply{path: path, status: resp.StatusCode, body: string(body), errMsg: parsed.Error}
}

// wantBrowse fails the test unless the reply has the given status and, when
// errMsg is non-empty, exactly that "error" text.
func wantBrowse(t *testing.T, got browseReply, status int, errMsg string) {
	t.Helper()
	if got.status != status || (errMsg != "" && got.errMsg != errMsg) {
		t.Errorf("browse %q: got %d %.200s; want %d with error %q", got.path, got.status, got.body, status, errMsg)
	}
}

// startBrowseModeB starts a centralized server (real auth, API keys on, from
// ciTestConfig) with the given source root and read-only flag.
func startBrowseModeB(t *testing.T, root string, readOnly bool) (addr, dbPath string) {
	t.Helper()
	cfg, dbPath := ciTestConfig(t)
	cfg.SourceRoot = root
	cfg.ReadOnly = readOnly
	addr, cleanup := startTestServer(t, cfg)
	t.Cleanup(cleanup)
	return addr, dbPath
}

// browseRoot creates the dedicated source root t.TempDir()/root.
func browseRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	return root
}

// browseOutsideDir creates a directory outside every t.TempDir() of the test.
func browseOutsideDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "vulture-browse-outside-")
	if err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// setBrowseTestUserRole sets a registered user's role in the SQLite test DB,
// as promoteUserToAdmin does for admins: /api/auth/register always creates a
// member. The auth middleware reloads the user on every request, so the new
// role applies to a token issued before the change.
func setBrowseTestUserRole(t *testing.T, dbPath, email, role string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	res, err := db.Exec(`UPDATE users SET role = ? WHERE email = ?`, role, email)
	if err != nil {
		t.Fatalf("set role %q: %v", role, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("set role %q: expected 1 row updated for %q, got %d", role, email, n)
	}
}

// mintBrowseAPIKey creates an API key as the given admin and returns it.
func mintBrowseAPIKey(t *testing.T, addr, adminToken string) string {
	t.Helper()
	resp, err := httpPostWithAuth(addr, "/api/api-keys", adminToken, map[string]string{"name": "browse-policy"})
	if err != nil {
		t.Fatalf("POST /api/api-keys: %v", err)
	}
	var key struct {
		Key string `json:"key"`
	}
	readJSON(t, resp, &key)
	if !strings.HasPrefix(key.Key, "vk_") {
		t.Fatalf("POST /api/api-keys: expected a vk_ key, got %q", key.Key)
	}
	return key.Key
}

// TestBrowse_CentralizedNoRoot_Refused: with no source root, a member's browse
// of an existing dir, a file, "/", a missing path, a denylisted path or a ".."
// spelling gets the same 403 and text. The refusal comes before the path is
// parsed or touched, so it reveals nothing about the filesystem.
func TestBrowse_CentralizedNoRoot_Refused(t *testing.T) {
	addr, dbPath := startBrowseModeB(t, "", false)
	member := registerAndLogin(t, addr, dbPath, "member@example.test", "member-password-1", false)
	dir := createTestSourceDir(t)

	for _, p := range []string{dir, filepath.Join(dir, "main.go"), "/", filepath.Join(dir, "missing"), "/etc", "/a/../b"} {
		wantBrowse(t, browseAs(t, addr, member, p), http.StatusForbidden, browseDisabledText)
	}
}

// TestBrowse_RoleGate: with a root set, only human writers may browse.
func TestBrowse_RoleGate(t *testing.T) {
	root := browseRoot(t)
	addr, dbPath := startBrowseModeB(t, root, false)
	admin := registerAndLogin(t, addr, dbPath, "admin@example.test", "admin-password-1", true)
	member := registerAndLogin(t, addr, dbPath, "member@example.test", "member-password-1", false)
	viewer := registerAndLogin(t, addr, dbPath, "viewer@example.test", "viewer-password-1", false)
	setBrowseTestUserRole(t, dbPath, "viewer@example.test", "viewer")
	apiKey := mintBrowseAPIKey(t, addr, admin)

	for _, c := range []struct {
		who, token string
		status     int
		errMsg     string
	}{
		{"viewer", viewer, http.StatusForbidden, browseRoleText},
		{"apikey", apiKey, http.StatusForbidden, browseRoleText},
		{"member", member, http.StatusOK, ""},
		{"admin", admin, http.StatusOK, ""},
	} {
		t.Run(c.who, func(t *testing.T) {
			wantBrowse(t, browseAs(t, addr, c.token, root), c.status, c.errMsg)
		})
	}
}

// TestBrowse_ReadOnly_Refused: a read-only server refuses every browse with
// the disabled text, with or without a root.
func TestBrowse_ReadOnly_Refused(t *testing.T) {
	t.Run("no root", func(t *testing.T) { browseReadOnlyRefused(t, "") })
	t.Run("root set", func(t *testing.T) { browseReadOnlyRefused(t, browseRoot(t)) })
}

// browseReadOnlyRefused browses an existing directory (the root when set) and
// "/" as a member of a read-only server.
func browseReadOnlyRefused(t *testing.T, root string) {
	t.Helper()
	addr, dbPath := startBrowseModeB(t, root, true)
	member := registerAndLogin(t, addr, dbPath, "member@example.test", "member-password-1", false)
	dir := root
	if dir == "" {
		dir = createTestSourceDir(t)
	}
	for _, p := range []string{dir, "/"} {
		wantBrowse(t, browseAs(t, addr, member, p), http.StatusForbidden, browseDisabledText)
	}
}

// TestBrowse_RootSet_OutsideRefusalsUniform: with a root set, an outside dir
// and an outside link that resolves into a denylisted tree get byte-identical
// 403 bodies, so the refusal does not tell the caller what the path is.
func TestBrowse_RootSet_OutsideRefusalsUniform(t *testing.T) {
	root := browseRoot(t)
	outside := browseOutsideDir(t)
	link := filepath.Join(outside, "etc-link")
	if err := os.Symlink("/etc", link); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}
	addr, dbPath := startBrowseModeB(t, root, false)
	member := registerAndLogin(t, addr, dbPath, "member@example.test", "member-password-1", false)

	dirReply := browseAs(t, addr, member, outside)
	linkReply := browseAs(t, addr, member, link)
	wantBrowse(t, dirReply, http.StatusForbidden, browseOutsideText)
	wantBrowse(t, linkReply, http.StatusForbidden, browseOutsideText)
	if dirReply.body != linkReply.body {
		t.Errorf("outside refusals differ: dir %s; link %s", dirReply.body, linkReply.body)
	}
}

// TestBrowse_RootSet_Confined pins confinement under a root: inside 200,
// outside 403, missing inside 404, an in-root link escaping the root 403.
func TestBrowse_RootSet_Confined(t *testing.T) {
	root := browseRoot(t)
	inside := filepath.Join(root, "project")
	if err := os.Mkdir(inside, 0o755); err != nil {
		t.Fatalf("mkdir inside: %v", err)
	}
	outside := browseOutsideDir(t)
	escape := filepath.Join(root, "escape")
	if err := os.Symlink(outside, escape); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}
	addr, dbPath := startBrowseModeB(t, root, false)
	member := registerAndLogin(t, addr, dbPath, "member@example.test", "member-password-1", false)

	for _, c := range []struct {
		path   string
		status int
	}{
		{inside, http.StatusOK},
		{outside, http.StatusForbidden},
		{filepath.Join(root, "missing"), http.StatusNotFound},
		{escape, http.StatusForbidden},
	} {
		wantBrowse(t, browseAs(t, addr, member, c.path), c.status, "")
	}
}

// TestBrowse_LocalMode_Unchanged pins local mode with no root and no token:
// the denylist is the only limit.
func TestBrowse_LocalMode_Unchanged(t *testing.T) {
	addr, cleanup := startTestServer(t, testConfig(t))
	defer cleanup()
	dir := createTestSourceDir(t)

	for _, c := range []struct {
		path   string
		status int
	}{
		{dir, http.StatusOK},
		{"/", http.StatusOK},
		{"/etc", http.StatusForbidden},
		{filepath.Join(dir, "missing"), http.StatusNotFound},
	} {
		wantBrowse(t, browseAs(t, addr, "", c.path), c.status, "")
	}
}
