//go:build e2e

package e2e

// Local-ingest confinement (feature 0102, CWE-22/203/59).
//
// POST /api/sources {"type":"local"} follows the local-path policy that
// folder browse follows:
//   - centralized with no VULTURE_SOURCE_ROOT: refused before the path is
//     looked at, with the policy's one disabled text (browseDisabledText) for
//     every path;
//   - root set: a path is accepted only when it is spelled under the root and
//     resolves to an existing directory inside it. Every other path gets ONE
//     byte-identical refusal, so a caller cannot tell missing, unreadable,
//     outside and linked-out apart (no existence oracle);
//   - inside the root, and in local mode, the errors stay helpful and name
//     the path;
//   - a stored local source that the current policy refuses is never handed
//     to an agent: its audit fails with a fixed reason.
//
// Fixtures follow browse_policy_test.go: a dedicated root t.TempDir()/root
// (browseRoot) and outside paths from os.MkdirTemp (browseOutsideDir).

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/vulture/backend/internal/config"
)

const (
	localIngestNotPermittedText = "path not permitted: must be an existing directory inside the source root"
	localIngestReadOnlyText     = "read-only mode: this Vulture instance does not accept writes"
	localIngestDispatchRefusal  = "source refused by the local-path policy"
	// localIngestHostileBound is the wall-clock limit for one hostile request.
	localIngestHostileBound = 2 * time.Second
	// localIngestMaxConfinedBytes is Linux PATH_MAX, the longest path that
	// confinement resolves at all.
	localIngestMaxConfinedBytes = 4096
)

// localIngestReply is one ingest response: its status, raw body, "error"
// text, and the stored source's id and path on success.
type localIngestReply struct {
	reqPath string
	status  int
	body    string
	errMsg  string
	srcID   string
	srcPath string
}

// localIngestCase is one expected ingest outcome; errMsg "" checks status only.
type localIngestCase struct {
	path   string
	status int
	errMsg string
}

// localIngestAs POSTs a local source for path, sending token as a Bearer
// credential when it is non-empty.
func localIngestAs(t *testing.T, addr, token, path string) localIngestReply {
	t.Helper()
	resp, err := httpPostWithAuth(addr, "/api/sources", token, map[string]string{"type": "local", "path": path})
	if err != nil {
		t.Fatalf("POST /api/sources %.120q: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read ingest reply for %.120q: %v", path, err)
	}
	var parsed struct {
		Error string `json:"error"`
		ID    string `json:"id"`
		Path  string `json:"path"`
	}
	_ = json.Unmarshal(body, &parsed)
	return localIngestReply{reqPath: path, status: resp.StatusCode, body: string(body),
		errMsg: parsed.Error, srcID: parsed.ID, srcPath: parsed.Path}
}

// wantLocalIngest fails the test unless the reply has the given status and,
// when errMsg is non-empty, exactly that "error" text.
func wantLocalIngest(t *testing.T, got localIngestReply, status int, errMsg string) {
	t.Helper()
	if got.status != status || (errMsg != "" && got.errMsg != errMsg) {
		t.Errorf("ingest %.120q: got %d %.300s; want %d with error %.300q", got.reqPath, got.status, got.body, status, errMsg)
	}
}

// wantStoredAsRequested fails the test unless a 201 stored the path exactly
// as it was requested.
func wantStoredAsRequested(t *testing.T, got localIngestReply) {
	t.Helper()
	if got.status == http.StatusCreated && got.srcPath != got.reqPath {
		t.Errorf("ingest %q: stored path %q; want the requested path", got.reqPath, got.srcPath)
	}
}

// wantUniformLocalIngest ingests every path and fails the test unless each
// reply is a 400 with exactly errMsg and every body is byte-identical.
func wantUniformLocalIngest(t *testing.T, addr, token string, paths []string, errMsg string) {
	t.Helper()
	var first localIngestReply
	for i, p := range paths {
		got := localIngestAs(t, addr, token, p)
		wantLocalIngest(t, got, http.StatusBadRequest, errMsg)
		if i == 0 {
			first = got
		} else if got.body != first.body {
			t.Errorf("refusals differ: %q got %.300s; %q got %.300s", first.reqPath, first.body, got.reqPath, got.body)
		}
	}
}

// localIngestMkdir creates dir and its parents and returns it.
func localIngestMkdir(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	return dir
}

// localIngestFile creates a small regular file and returns its path.
func localIngestFile(t *testing.T, path string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// localIngestSymlink creates link -> target and returns link.
func localIngestSymlink(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}
	return link
}

// localIngestLockedDir creates parent/locked/inner and sets parent/locked to
// mode 000, restoring it at cleanup. It returns "" when the test runs as
// root, which ignores the mode.
func localIngestLockedDir(t *testing.T, parent string) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Log("running as root: mode 000 does not make a directory unreadable; unreadable cases skipped")
		return ""
	}
	locked := filepath.Join(parent, "locked")
	localIngestMkdir(t, filepath.Join(locked, "inner"))
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatalf("chmod %s: %v", locked, err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	return locked
}

// localIngestUnreadable returns a mode-000 directory under parent and a path
// below it, or nothing when running as root.
func localIngestUnreadable(t *testing.T, parent string) []string {
	t.Helper()
	locked := localIngestLockedDir(t, parent)
	if locked == "" {
		return nil
	}
	return []string{locked, filepath.Join(locked, "inner")}
}

// localIngestPathOfLen appends seg to prefix as often as the result stays at
// most n bytes.
func localIngestPathOfLen(prefix, seg string, n int) string {
	return prefix + strings.Repeat(seg, (n-len(prefix))/len(seg))
}

// localIngestRows counts the sources rows stored with exactly path.
func localIngestRows(t *testing.T, dbPath, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sources WHERE path = ?`, path).Scan(&n); err != nil {
		t.Fatalf("count sources: %v", err)
	}
	return n
}

// localIngestMember registers a member on the server at addr and returns its
// token.
func localIngestMember(t *testing.T, addr, dbPath string) string {
	t.Helper()
	return registerAndLogin(t, addr, dbPath, "member@example.test", "member-password-1", false)
}

// startLocalIngestMember starts a centralized server (browse_policy_test.go's
// startBrowseModeB) and returns its address and a member's token.
func startLocalIngestMember(t *testing.T, root string, readOnly bool) (addr, token string) {
	t.Helper()
	addr, dbPath := startBrowseModeB(t, root, readOnly)
	return addr, localIngestMember(t, addr, dbPath)
}

// TestLocalIngest_CentralizedNoRoot_RefusesUniformly: with no source root,
// every local path gets the policy's disabled text in a byte-identical 400,
// whether it is the caller's own directory, a file, missing, unreadable or a
// system directory. Nothing is looked at, so nothing is revealed.
func TestLocalIngest_CentralizedNoRoot_RefusesUniformly(t *testing.T) {
	addr, member := startLocalIngestMember(t, "", false)
	dir := createTestSourceDir(t)
	paths := []string{dir, filepath.Join(dir, "main.go"), filepath.Join(dir, "missing"), "/etc"}
	paths = append(paths, localIngestUnreadable(t, dir)...)

	wantUniformLocalIngest(t, addr, member, paths, browseDisabledText)
}

// TestLocalIngest_OutsideRoot_RefusesUniformly: with a root set, every path
// that is not an existing directory spelled and resolved inside the root gets
// the same 400: an outside directory, file, missing or unreadable path; an
// in-root link to an outside directory, file or missing target; and an
// outside link that resolves INTO the root.
func TestLocalIngest_OutsideRoot_RefusesUniformly(t *testing.T) {
	root := browseRoot(t)
	project := localIngestMkdir(t, filepath.Join(root, "project"))
	outside := browseOutsideDir(t)
	file := localIngestFile(t, filepath.Join(outside, "file.txt"))
	missing := filepath.Join(outside, "missing")
	paths := []string{
		outside, file, missing,
		localIngestSymlink(t, outside, filepath.Join(root, "to-dir")),
		localIngestSymlink(t, file, filepath.Join(root, "to-file")),
		localIngestSymlink(t, missing, filepath.Join(root, "to-missing")),
		localIngestSymlink(t, project, filepath.Join(outside, "into-root")),
	}
	paths = append(paths, localIngestUnreadable(t, outside)...)
	addr, member := startLocalIngestMember(t, root, false)

	wantUniformLocalIngest(t, addr, member, paths, localIngestNotPermittedText)
}

// TestLocalIngest_DotDotThroughSymlink_Refused: R/repo/lnk/../secret, with
// R/repo/lnk -> <outside>/a, is <outside>/secret to the kernel but
// R/repo/secret to a lexical clean. It must be refused, and no source row may
// be stored under that spelling.
func TestLocalIngest_DotDotThroughSymlink_Refused(t *testing.T) {
	root := browseRoot(t)
	outside := browseOutsideDir(t)
	localIngestMkdir(t, filepath.Join(outside, "a"))
	localIngestMkdir(t, filepath.Join(outside, "secret"))
	localIngestMkdir(t, filepath.Join(root, "repo"))
	localIngestSymlink(t, filepath.Join(outside, "a"), filepath.Join(root, "repo", "lnk"))
	// Concatenated, not filepath.Join, which would clean the ".." away.
	bypass := root + "/repo/lnk/../secret"
	if info, err := os.Stat(bypass); err != nil || !info.IsDir() {
		t.Fatalf("fixture: %q must resolve to the outside directory: %v", bypass, err)
	}
	addr, dbPath := startBrowseModeB(t, root, false)
	member := localIngestMember(t, addr, dbPath)

	wantLocalIngest(t, localIngestAs(t, addr, member, bypass), http.StatusBadRequest, localIngestNotPermittedText)
	if n := localIngestRows(t, dbPath, bypass); n != 0 {
		t.Errorf("sources holds %d row(s) with path %q; want none", n, bypass)
	}
}

// TestLocalIngest_InsideRoot_HelpfulErrors: inside the root the caller may
// learn what the path is, so the errors name it. A directory, and an absolute
// in-root symlink to one, are stored under the requested spelling.
func TestLocalIngest_InsideRoot_HelpfulErrors(t *testing.T) {
	root := browseRoot(t)
	project := localIngestMkdir(t, filepath.Join(root, "project"))
	release := localIngestMkdir(t, filepath.Join(root, "releases", "v2"))
	current := localIngestSymlink(t, release, filepath.Join(root, "current"))
	file := localIngestFile(t, filepath.Join(root, "notes.txt"))
	missing := filepath.Join(root, "missing")
	cases := []localIngestCase{
		{missing, http.StatusBadRequest, "path does not exist: " + missing},
		{file, http.StatusBadRequest, "path is not a directory: " + file},
		{project, http.StatusCreated, ""},
		{current, http.StatusCreated, ""},
	}
	cases = append(cases, localIngestUnreadableCase(t, root)...)
	addr, member := startLocalIngestMember(t, root, false)

	for _, c := range cases {
		got := localIngestAs(t, addr, member, c.path)
		wantLocalIngest(t, got, c.status, c.errMsg)
		wantStoredAsRequested(t, got)
	}
}

// localIngestUnreadableCase is the expected reply for a path below a mode-000
// directory inside root, or nothing when running as root.
func localIngestUnreadableCase(t *testing.T, root string) []localIngestCase {
	t.Helper()
	locked := localIngestLockedDir(t, root)
	if locked == "" {
		return nil
	}
	inner := filepath.Join(locked, "inner")
	return []localIngestCase{{inner, http.StatusBadRequest, "path is not readable by the server: " + inner}}
}

// TestLocalIngest_HostileInput_Bounded: with a root set, a 64 KiB path and a
// PATH_MAX-long walk through a self-referencing link each get the uniform 400
// within the time bound.
func TestLocalIngest_HostileInput_Bounded(t *testing.T) {
	root := browseRoot(t)
	loop := localIngestSymlink(t, "loop", filepath.Join(root, "loop"))
	paths := []string{
		localIngestPathOfLen(root, "/d", 64<<10),
		localIngestPathOfLen(loop, "/loop", localIngestMaxConfinedBytes),
	}
	addr, member := startLocalIngestMember(t, root, false)

	for _, p := range paths {
		start := time.Now()
		got := localIngestAs(t, addr, member, p)
		if d := time.Since(start); d > localIngestHostileBound {
			t.Errorf("ingest of a %d-byte path took %v; want under %v", len(p), d, localIngestHostileBound)
		}
		wantLocalIngest(t, got, http.StatusBadRequest, localIngestNotPermittedText)
	}
}

// TestLocalIngest_LocalMode_NamesPath pins local mode: an ingest error names
// the requested path, which is what a local user needs to fix a mount.
func TestLocalIngest_LocalMode_NamesPath(t *testing.T) {
	addr, cleanup := startTestServer(t, testConfig(t))
	defer cleanup()
	dir := createTestSourceDir(t)

	for _, p := range []string{filepath.Join(dir, "missing"), filepath.Join(dir, "main.go")} {
		got := localIngestAs(t, addr, "", p)
		if got.status != http.StatusBadRequest || !strings.Contains(got.errMsg, p) {
			t.Errorf("local ingest %q: got %d %.300s; want 400 naming the path", p, got.status, got.body)
		}
	}
}

// localPathsMode starts a server in one mode and returns its address, the
// token to send (empty in local mode) and a directory the mode may confine.
type localPathsMode func(t *testing.T) (addr, token, dir string)

// startLocalPathsLocal is local mode: no root and no token.
func startLocalPathsLocal(t *testing.T) (addr, token, dir string) {
	t.Helper()
	addr, cleanup := startTestServer(t, testConfig(t))
	t.Cleanup(cleanup)
	return addr, "", createTestSourceDir(t)
}

// startLocalPathsCentral is a centralized mode for a member: with a dedicated
// root holding the directory when withRoot, and read-only when readOnly.
func startLocalPathsCentral(withRoot, readOnly bool) localPathsMode {
	return func(t *testing.T) (string, string, string) {
		t.Helper()
		root, dir := "", createTestSourceDir(t)
		if withRoot {
			root = browseRoot(t)
			dir = localIngestMkdir(t, filepath.Join(root, "project"))
		}
		addr, member := startLocalIngestMember(t, root, readOnly)
		return addr, member, dir
	}
}

// TestLocalPaths_BrowseAndIngestAgree: browse and ingest answer the same
// directory consistently in every mode, as explicit (browse, ingest) pairs.
// Read-only ingest is refused by the read-only guard before the policy runs.
func TestLocalPaths_BrowseAndIngestAgree(t *testing.T) {
	for _, c := range []struct {
		name         string
		start        localPathsMode
		browseStatus int
		browseErr    string
		ingestStatus int
		ingestErr    string
	}{
		{"local", startLocalPathsLocal, http.StatusOK, "", http.StatusCreated, ""},
		{"centralized no root", startLocalPathsCentral(false, false),
			http.StatusForbidden, browseDisabledText, http.StatusBadRequest, browseDisabledText},
		{"centralized root inside dir", startLocalPathsCentral(true, false), http.StatusOK, "", http.StatusCreated, ""},
		{"read-only", startLocalPathsCentral(true, true),
			http.StatusForbidden, browseDisabledText, http.StatusServiceUnavailable, localIngestReadOnlyText},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, token, dir := c.start(t)
			wantBrowse(t, browseAs(t, addr, token, dir), c.browseStatus, c.browseErr)
			wantLocalIngest(t, localIngestAs(t, addr, token, dir), c.ingestStatus, c.ingestErr)
		})
	}
}

// localIngestAudit is the subset of an audit this file reads off the API.
type localIngestAudit struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	DegradedReason string `json:"degraded_reason"`
}

// localIngestTerminal holds the audit statuses that end a poll.
var localIngestTerminal = map[string]bool{"completed": true, "failed": true}

// localIngestStoredSource stores a local source through a local-mode server,
// stops that server, and returns its database and the source's id.
func localIngestStoredSource(t *testing.T) (dbPath, sourceID string) {
	t.Helper()
	cfg := testConfig(t)
	addr, stop := startTestServer(t, cfg)
	stored := localIngestAs(t, addr, "", createTestSourceDir(t))
	stop()
	if stored.status != http.StatusCreated || stored.srcID == "" {
		t.Fatalf("local-mode ingest: got %d %.300s; want 201 with an id", stored.status, stored.body)
	}
	return cfg.DBPath, stored.srcID
}

// localIngestRunAudit creates a cwe audit of sourceID as token's principal and
// polls it to a terminal status.
func localIngestRunAudit(t *testing.T, addr, token, sourceID string) localIngestAudit {
	t.Helper()
	resp, err := httpPostWithAuth(addr, "/api/audits", token, map[string]interface{}{
		"source_id": sourceID, "types": []string{"cwe"},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	var created localIngestAudit
	readJSON(t, resp, &created)
	if created.ID == "" {
		t.Fatalf("POST /api/audits: status %d, no audit id", resp.StatusCode)
	}
	return localIngestPollAudit(t, addr, token, created.ID)
}

// localIngestPollAudit polls GET /api/audits/{id} with token until the audit
// reaches a terminal status.
func localIngestPollAudit(t *testing.T, addr, token, id string) localIngestAudit {
	t.Helper()
	var got localIngestAudit
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		resp, err := httpGetWithAuth(addr, "/api/audits/"+id, token)
		if err != nil {
			t.Fatalf("GET /api/audits/%s: %v", id, err)
		}
		readJSON(t, resp, &got)
		if localIngestTerminal[got.Status] {
			return got
		}
	}
	t.Fatalf("audit %s never reached a terminal status; last %+v", id, got)
	return got
}

// localIngestAgentCalls is the number of /run requests the scripted agent got.
func localIngestAgentCalls(a *scriptedAgent) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// TestLocalIngest_StoredRowOutsidePolicyNotScanned: a local source stored by
// a local-mode server is not scanned after the same database is served
// centralized with no root. Dispatch re-checks the stored path, fails the
// audit with a fixed reason, and never calls an agent.
func TestLocalIngest_StoredRowOutsidePolicyNotScanned(t *testing.T) {
	dbPath, sourceID := localIngestStoredSource(t)
	agent := newScriptedAgent(t, `{"findings":[],"summary":"cwe","score":100}`)
	cfg, _ := ciTestConfig(t)
	cfg.DBPath, cfg.SourceRoot = dbPath, ""
	cfg.Agents = map[string]config.AgentConfig{"cwe": {Name: "CWE", Type: "cwe", URL: agent.srv.URL}}
	addr, stop := startTestServer(t, cfg)
	t.Cleanup(stop)
	member := localIngestMember(t, addr, dbPath)

	final := localIngestRunAudit(t, addr, member, sourceID)
	if final.Status != "failed" || final.DegradedReason != localIngestDispatchRefusal {
		t.Errorf("audit of a stored source outside the policy: status %q, reason %q; want failed with %q",
			final.Status, final.DegradedReason, localIngestDispatchRefusal)
	}
	if n := localIngestAgentCalls(agent); n != 0 {
		t.Errorf("the agent got %d /run request(s) for a source outside the policy; want 0", n)
	}
}
