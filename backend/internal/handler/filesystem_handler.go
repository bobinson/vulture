package handler

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vulture/backend/internal/pathutil"
)

// FilesystemHandler serves directory listings for the folder browser.
//
// It follows the server's local-path policy (pathutil.LocalSources, 0102).
// A disabled policy (centralized mode without VULTURE_SOURCE_ROOT, or any
// read-only server) refuses every browse with one text before the path is
// parsed or touched. With a root, browse is confined to paths whose
// canonical (EvalSymlinks) form is inside it (0036 Phase 3), and the
// directory is stat'd and listed through an os.Root opened at the root, so
// a link swapped in after the check cannot make either describe anything
// outside it. The system denylist applies in every mode; local mode with no
// root can list the rest of what the process can read (dev laptops only).
type FilesystemHandler struct {
	local pathutil.LocalSources
}

// maxBrowseEntries caps the number of entries returned per directory
// listing. Prevents enormous responses (and slow renders) on directories
// like /var/log or /tmp with thousands of files.
const maxBrowseEntries = 1000

// NewFilesystemHandler creates a FilesystemHandler that follows the given
// local-path policy (required: the zero value refuses every browse).
func NewFilesystemHandler(local pathutil.LocalSources) *FilesystemHandler {
	return &FilesystemHandler{local: local}
}

type dirEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size,omitempty"`
}

type browseResponse struct {
	Path    string     `json:"path"`
	Parent  string     `json:"parent"`
	Entries []dirEntry `json:"entries"`
}

// Browse handles GET /api/filesystem/browse?path=...
func (h *FilesystemHandler) Browse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	dir, code, msg := h.resolve(r.URL.Query().Get("path"))
	if code != 0 {
		writeBrowseRefusal(w, r, code, msg)
		return
	}

	entries, err := listDir(dir)
	if err != nil {
		writeInternalError(w, r, "read directory", err)
		return
	}

	result := browseResponse{
		Path:    dir.Path(),
		Parent:  filepath.Dir(dir.Path()),
		Entries: entries,
	}
	writeJSON(w, http.StatusOK, result)
}

// listDir lists dir through an os.Root opened on it. With a source root that
// is the directory the check accepted, never one a link swapped in since
// points to. fs.ReadDir sorts by name as os.ReadDir does, and an entry read
// from a directory opened in an os.Root carries its FileInfo, lstat'd
// relative to that directory, so the sizes come through it too.
func listDir(dir pathutil.Confined) ([]dirEntry, error) {
	root, err := dir.OpenDir()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, err
	}
	return buildDirEntries(dir.Path(), entries), nil
}

// resolve applies the local-path policy, then validates reqPath against the
// policy's root. A disabled policy answers 403 with its own text before
// reqPath is parsed or any syscall is made. Its one 5xx is a root fault.
func (h *FilesystemHandler) resolve(reqPath string) (pathutil.Confined, int, string) {
	if err := h.local.Allow(); err != nil {
		return pathutil.Confined{}, http.StatusForbidden, err.Error()
	}
	return validateBrowsePathWithRoot(reqPath, h.local.Root)
}

// writeBrowseRefusal answers a path resolve refused. A 4xx is the caller's,
// answered with resolve's literal text. A 5xx is the server's: like every 500
// it goes through writeInternalError, so the body is the generic one with a
// request id, and msg goes only to the log line for that id.
func writeBrowseRefusal(w http.ResponseWriter, r *http.Request, code int, msg string) {
	if code >= http.StatusInternalServerError {
		writeInternalError(w, r, "browse", errors.New(msg))
		return
	}
	writeError(w, code, msg)
}

// validateBrowsePath retains the old signature for callers that
// haven't been updated — equivalent to calling
// validateBrowsePathWithRoot with an empty SourceRoot (legacy
// denylist-only behaviour).
func validateBrowsePath(reqPath string) (string, int, string) {
	dir, code, msg := validateBrowsePathWithRoot(reqPath, "")
	return dir.Path(), code, msg
}

// validateBrowsePathWithRoot is the Phase-3 validator. Confinement
// behaviour:
//   - Reject literal ".." segments at parse time (defence in depth;
//     filepath.Clean would silently normalise them out, but we want a
//     clear 400 so the caller knows their request was malformed).
//   - Resolve the path via filepath.Abs + filepath.Clean +
//     filepath.EvalSymlinks. Symlinks pointing outside the configured
//     root are rejected.
//   - When sourceRoot is non-empty, enforce that the canonical
//     resolved path is inside sourceRoot (using a path-separator
//     boundary so /tmp/sourcesXYZ doesn't match /tmp/sources). This
//     runs BEFORE the denylist (0102), so every outside path gets the
//     same refusal, whatever tree it resolves into.
//   - Apply the system-path denylist regardless of root (so even an
//     operator who sets SourceRoot=/ can't accidentally expose /etc).
//   - Stat the directory, through the root when there is one, and return
//     it confined, so Browse lists it through the root as well.
func validateBrowsePathWithRoot(reqPath, sourceRoot string) (pathutil.Confined, int, string) {
	// Defence-in-depth: reject literal ".." segments. filepath.Clean
	// would normalise these silently; a 400 surfaces the intent.
	if containsParentDirSegment(reqPath) {
		return pathutil.Confined{}, http.StatusBadRequest, "invalid path: '..' segments not allowed"
	}
	if reqPath == "" {
		reqPath = "/"
	}
	absPath, err := filepath.Abs(reqPath)
	if err != nil {
		return pathutil.Confined{}, http.StatusBadRequest, "invalid path"
	}
	absPath = filepath.Clean(absPath)
	// Resolve symlinks before checking the source root + blocklist.
	resolved, err := filepath.EvalSymlinks(absPath)
	if err == nil {
		absPath = resolved
	}
	// 0065 §M3 — one confinement implementation shared with local ingest.
	// Confine resolves the deepest existing ancestor's symlinks so a
	// symlinked parent cannot escape; empty sourceRoot is a no-op (legacy
	// denylist-only behaviour).
	dir, err := pathutil.Confine(sourceRoot, absPath)
	if err != nil {
		code, msg := confinementRefusal(err)
		return pathutil.Confined{}, code, msg
	}
	if isBlockedPath(absPath) {
		return pathutil.Confined{}, http.StatusForbidden, "access denied"
	}
	err = dir.StatDir()
	if errors.Is(err, pathutil.ErrNotDir) {
		return pathutil.Confined{}, http.StatusBadRequest, "path is not a directory"
	}
	if err != nil {
		return pathutil.Confined{}, http.StatusNotFound, "path not found"
	}
	return dir, 0, ""
}

// confinementRefusal answers a path confinement refused: a root fault is the
// server's (500, its cause logged at ERROR as source_root_unavailable), and
// every other refusal is the one 403 an outside path gets. Neither text names
// a path or the root.
func confinementRefusal(err error) (int, string) {
	if errors.Is(err, pathutil.ErrRootUnavailable) {
		slog.Error("source_root_unavailable", "err", err)
		return http.StatusInternalServerError, pathutil.ErrRootUnavailable.Error()
	}
	return http.StatusForbidden, "access denied: path outside source root"
}

// containsParentDirSegment returns true if any path component is
// exactly "..". Works on both / and \ separators (defensive).
func containsParentDirSegment(p string) bool {
	for _, sep := range []rune{'/', filepath.Separator} {
		for _, part := range strings.Split(p, string(sep)) {
			if part == ".." {
				return true
			}
		}
	}
	return false
}

func buildDirEntries(absPath string, entries []os.DirEntry) []dirEntry {
	// 0036 Phase 3 — cap at maxBrowseEntries to prevent enormous
	// responses on directories with thousands of files (e.g. /var/log
	// archives, exploded node_modules trees). Entries past the cap are
	// dropped silently; the SPA shows the visible subset.
	capHint := len(entries)
	if capHint > maxBrowseEntries {
		capHint = maxBrowseEntries
	}
	result := make([]dirEntry, 0, capHint)
	for _, e := range entries {
		if len(result) >= maxBrowseEntries {
			break
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		entry := dirEntry{
			Name:  name,
			Path:  filepath.Join(absPath, name),
			IsDir: e.IsDir(),
		}
		if fi, err := e.Info(); err == nil {
			entry.Size = fi.Size()
		}
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].IsDir != result[j].IsDir {
			return result[i].IsDir
		}
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	return result
}

// isBlockedPath prevents browsing sensitive system directories.
func isBlockedPath(path string) bool {
	blocked := []string{
		"/proc", "/sys", "/dev", "/run",
		"/boot", "/lost+found",
		"/etc", "/root", "/var",
		"/snap", "/sbin", "/bin",
		"/lib", "/lib64", "/usr",
	}
	for _, b := range blocked {
		if path == b || strings.HasPrefix(path, b+"/") {
			return true
		}
	}
	return false
}
