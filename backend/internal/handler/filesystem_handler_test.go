package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFilesystemHandlerBrowse(t *testing.T) {
	// Create a temp directory with some files
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	os.WriteFile(filepath.Join(dir, "file.txt"), []byte("hello"), 0644)

	h := NewFilesystemHandler()
	req := httptest.NewRequest("GET", "/api/filesystem/browse?path="+dir, nil)
	w := httptest.NewRecorder()
	h.Browse(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result browseResponse
	json.NewDecoder(w.Body).Decode(&result)
	if result.Path != dir {
		t.Errorf("expected path %s, got %s", dir, result.Path)
	}
	// subdir should come first (dirs before files)
	if len(result.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result.Entries))
	}
	if result.Entries[0].Name != "subdir" || !result.Entries[0].IsDir {
		t.Errorf("first entry should be subdir, got %s isDir=%v", result.Entries[0].Name, result.Entries[0].IsDir)
	}
	if result.Entries[1].Name != "file.txt" || result.Entries[1].IsDir {
		t.Errorf("second entry should be file.txt, got %s", result.Entries[1].Name)
	}
}

func TestFilesystemHandlerBrowseDefaultPath(t *testing.T) {
	h := NewFilesystemHandler()
	req := httptest.NewRequest("GET", "/api/filesystem/browse", nil)
	w := httptest.NewRecorder()
	h.Browse(w, req)

	// Default path "/" should work
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFilesystemHandlerBrowseHiddenFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".hidden"), []byte("secret"), 0644)
	os.WriteFile(filepath.Join(dir, "visible.txt"), []byte("hello"), 0644)

	h := NewFilesystemHandler()
	req := httptest.NewRequest("GET", "/api/filesystem/browse?path="+dir, nil)
	w := httptest.NewRecorder()
	h.Browse(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result browseResponse
	json.NewDecoder(w.Body).Decode(&result)
	// Hidden files should be excluded
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry (hidden excluded), got %d", len(result.Entries))
	}
	if result.Entries[0].Name != "visible.txt" {
		t.Errorf("expected visible.txt, got %s", result.Entries[0].Name)
	}
}

func TestFilesystemHandlerBrowseNotFound(t *testing.T) {
	h := NewFilesystemHandler()
	req := httptest.NewRequest("GET", "/api/filesystem/browse?path=/nonexistent_path_xyz", nil)
	w := httptest.NewRecorder()
	h.Browse(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestFilesystemHandlerBrowseNotDir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(f, []byte("hello"), 0644)

	h := NewFilesystemHandler()
	req := httptest.NewRequest("GET", "/api/filesystem/browse?path="+f, nil)
	w := httptest.NewRecorder()
	h.Browse(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestFilesystemHandlerBrowseBlockedPath(t *testing.T) {
	h := NewFilesystemHandler()
	req := httptest.NewRequest("GET", "/api/filesystem/browse?path=/proc", nil)
	w := httptest.NewRecorder()
	h.Browse(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestFilesystemHandlerBrowseBlockedSubpath(t *testing.T) {
	h := NewFilesystemHandler()
	req := httptest.NewRequest("GET", "/api/filesystem/browse?path=/sys/kernel", nil)
	w := httptest.NewRecorder()
	h.Browse(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestFilesystemHandlerBrowseMethodNotAllowed(t *testing.T) {
	h := NewFilesystemHandler()
	req := httptest.NewRequest("POST", "/api/filesystem/browse", nil)
	w := httptest.NewRecorder()
	h.Browse(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestIsBlockedPath(t *testing.T) {
	tests := []struct {
		path    string
		blocked bool
	}{
		{"/proc", true},
		{"/proc/1/status", true},
		{"/sys", true},
		{"/sys/kernel", true},
		{"/dev", true},
		{"/dev/null", true},
		{"/run", true},
		{"/boot", true},
		{"/lost+found", true},
		{"/home", false},
		{"/tmp", false},
		{"/", false},
		{"/processes", false}, // /proc prefix but not /proc/
	}
	for _, tc := range tests {
		got := isBlockedPath(tc.path)
		if got != tc.blocked {
			t.Errorf("isBlockedPath(%q) = %v, want %v", tc.path, got, tc.blocked)
		}
	}
}

func TestBuildDirEntries(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "beta"), 0755)
	os.MkdirAll(filepath.Join(dir, "alpha"), 0755)
	os.WriteFile(filepath.Join(dir, "zebra.txt"), []byte("z"), 0644)
	os.WriteFile(filepath.Join(dir, "apple.txt"), []byte("a"), 0644)

	entries, _ := os.ReadDir(dir)
	result := buildDirEntries(dir, entries)

	// Dirs first (alpha, beta), then files (apple.txt, zebra.txt)
	if len(result) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(result))
	}
	if result[0].Name != "alpha" || !result[0].IsDir {
		t.Errorf("first should be alpha dir, got %s", result[0].Name)
	}
	if result[1].Name != "beta" || !result[1].IsDir {
		t.Errorf("second should be beta dir, got %s", result[1].Name)
	}
	if result[2].Name != "apple.txt" || result[2].IsDir {
		t.Errorf("third should be apple.txt file, got %s", result[2].Name)
	}
	if result[3].Name != "zebra.txt" || result[3].IsDir {
		t.Errorf("fourth should be zebra.txt file, got %s", result[3].Name)
	}
}

func TestValidateBrowsePath(t *testing.T) {
	dir := t.TempDir()

	absPath, code, msg := validateBrowsePath(dir)
	if code != 0 {
		t.Fatalf("expected no error, got code=%d msg=%s", code, msg)
	}
	if absPath != dir {
		t.Errorf("expected %s, got %s", dir, absPath)
	}
}
