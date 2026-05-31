package handler

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FilesystemHandler serves directory listings for the folder browser.
//
// 0036 Phase 3 — confinement: when SourceRoot is non-empty, browse
// requests are constrained to paths whose canonical (EvalSymlinks)
// form is inside SourceRoot. Empty SourceRoot falls back to the
// pre-Phase-3 denylist behaviour (system paths are blocked but the
// rest of the filesystem readable by the process is browsable —
// acceptable for dev laptops, NOT for Mode B).
type FilesystemHandler struct {
	SourceRoot string
}

// maxBrowseEntries caps the number of entries returned per directory
// listing. Prevents enormous responses (and slow renders) on directories
// like /var/log or /tmp with thousands of files.
const maxBrowseEntries = 1000

// NewFilesystemHandler creates a new FilesystemHandler.
func NewFilesystemHandler() *FilesystemHandler {
	return &FilesystemHandler{}
}

// SetSourceRoot configures the confinement root. When non-empty, browse
// rejects paths outside the canonical form of root with 403.
func (h *FilesystemHandler) SetSourceRoot(root string) {
	h.SourceRoot = root
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

	absPath, code, msg := validateBrowsePathWithRoot(
		r.URL.Query().Get("path"), h.SourceRoot,
	)
	if code != 0 {
		writeError(w, code, msg)
		return
	}

	entries, err := os.ReadDir(absPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot read directory")
		return
	}

	result := browseResponse{
		Path:    absPath,
		Parent:  filepath.Dir(absPath),
		Entries: buildDirEntries(absPath, entries),
	}
	writeJSON(w, http.StatusOK, result)
}

// validateBrowsePath retains the old signature for callers that
// haven't been updated — equivalent to calling
// validateBrowsePathWithRoot with an empty SourceRoot (legacy
// denylist-only behaviour).
func validateBrowsePath(reqPath string) (string, int, string) {
	return validateBrowsePathWithRoot(reqPath, "")
}

// validateBrowsePathWithRoot is the Phase-3 validator. Confinement
// behaviour:
//   - Reject literal ".." segments at parse time (defence in depth;
//     filepath.Clean would silently normalise them out, but we want a
//     clear 400 so the caller knows their request was malformed).
//   - Resolve the path via filepath.Abs + filepath.Clean +
//     filepath.EvalSymlinks. Symlinks pointing outside the configured
//     root are rejected.
//   - Apply the system-path denylist regardless of root (so even an
//     operator who sets SourceRoot=/ can't accidentally expose /etc).
//   - When sourceRoot is non-empty, enforce that the canonical
//     resolved path is inside sourceRoot (using a path-separator
//     boundary so /tmp/sourcesXYZ doesn't match /tmp/sources).
func validateBrowsePathWithRoot(reqPath, sourceRoot string) (string, int, string) {
	// Defence-in-depth: reject literal ".." segments. filepath.Clean
	// would normalise these silently; a 400 surfaces the intent.
	if containsParentDirSegment(reqPath) {
		return "", http.StatusBadRequest, "invalid path: '..' segments not allowed"
	}
	if reqPath == "" {
		reqPath = "/"
	}
	absPath, err := filepath.Abs(reqPath)
	if err != nil {
		return "", http.StatusBadRequest, "invalid path"
	}
	absPath = filepath.Clean(absPath)
	// Resolve symlinks before checking the blocklist + source root.
	resolved, err := filepath.EvalSymlinks(absPath)
	if err == nil {
		absPath = resolved
	}
	if isBlockedPath(absPath) {
		return "", http.StatusForbidden, "access denied"
	}
	if sourceRoot != "" {
		canonRoot, err := filepath.EvalSymlinks(filepath.Clean(sourceRoot))
		if err != nil {
			canonRoot = filepath.Clean(sourceRoot)
		}
		if !pathInsideRoot(absPath, canonRoot) {
			return "", http.StatusForbidden, "access denied: path outside source root"
		}
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return "", http.StatusNotFound, "path not found"
	}
	if !info.IsDir() {
		return "", http.StatusBadRequest, "path is not a directory"
	}
	return absPath, 0, ""
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

// pathInsideRoot returns true if `path` equals `root` or is contained
// inside `root` using a separator boundary (so /a/b is NOT inside /a/bc).
func pathInsideRoot(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(os.PathSeparator))
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
