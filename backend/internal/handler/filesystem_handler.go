package handler

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FilesystemHandler serves directory listings for the folder browser.
type FilesystemHandler struct{}

// NewFilesystemHandler creates a new FilesystemHandler.
func NewFilesystemHandler() *FilesystemHandler {
	return &FilesystemHandler{}
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

	absPath, code, msg := validateBrowsePath(r.URL.Query().Get("path"))
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

func validateBrowsePath(reqPath string) (string, int, string) {
	if reqPath == "" {
		reqPath = "/"
	}
	absPath, err := filepath.Abs(reqPath)
	if err != nil {
		return "", http.StatusBadRequest, "invalid path"
	}
	absPath = filepath.Clean(absPath)
	// Resolve symlinks before checking the blocklist to prevent symlink escape
	resolved, err := filepath.EvalSymlinks(absPath)
	if err == nil {
		absPath = resolved
	}
	if isBlockedPath(absPath) {
		return "", http.StatusForbidden, "access denied"
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

func buildDirEntries(absPath string, entries []os.DirEntry) []dirEntry {
	result := make([]dirEntry, 0, len(entries))
	for _, e := range entries {
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
