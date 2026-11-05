package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/pathutil"
	"github.com/vulture/backend/internal/repository"
)

// Local ingest under the local-path policy (feature 0102, CWE-22/203). The
// policy decides before the filesystem is touched, and every refusal maps to
// client text that says nothing about a path the caller may not see.

const (
	localDisabledText     = "local paths are disabled on this server: set VULTURE_SOURCE_ROOT to allow them in centralized mode"
	localNotPermittedText = "path not permitted: must be an existing directory inside the source root"
)

// wantLocalDisabled fails unless err is the policy's disabled refusal with its
// exact client text.
func wantLocalDisabled(t *testing.T, p string, err error) {
	t.Helper()
	if !errors.Is(err, pathutil.ErrLocalSourcesDisabled) || err.Error() != localDisabledText {
		t.Errorf("path %.80q: got %v; want the disabled refusal %q", p, err, localDisabledText)
	}
}

// TestCheckLocalPath_DisabledBeforeFS: with local paths disabled, a
// directory, a file, a missing path, an unreadable path, a system directory,
// a relative path and an over-long path all get the same refusal, which only
// holds if none of them is looked at; and a refused ingest never reaches the
// repository.
func TestCheckLocalPath_DisabledBeforeFS(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "main.go")
	if err := os.WriteFile(file, []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repo := &repository.MockAuditRepository{
		FindSourceByPathFn: func(string) (*model.Source, error) {
			t.Error("a refused ingest reached the repository")
			return nil, nil
		},
	}
	svc := NewSourceServiceWithPolicy(repo, SourcePolicy{Local: pathutil.NewLocalSources("", false, false)})
	impl := svc.(*sourceService)
	paths := []string{dir, file, filepath.Join(dir, "missing"), lockedChildPath(t, dir), "/etc", "relative/dir",
		strings.Repeat("/x", pathutil.MaxConfinedPathBytes)}
	for _, p := range paths {
		wantLocalDisabled(t, p, impl.checkLocalPath(p))
		_, err := svc.Ingest(context.Background(), &model.SourceRequest{Type: string(model.SourceTypeLocal), Path: p})
		wantLocalDisabled(t, p, err)
	}
}

// lockedChildPath returns parent/locked/inner after setting parent/locked to
// mode 000 (restored at cleanup), so a stat of the path would be refused.
func lockedChildPath(t *testing.T, parent string) string {
	t.Helper()
	locked := filepath.Join(parent, "locked")
	if err := os.MkdirAll(filepath.Join(locked, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	return filepath.Join(locked, "inner")
}

// TestLocalPathError_Mapping: the first matching row wins. Only a failure
// found after confinement (inside the root, or in local mode) names the path;
// anything unrecognised under a root gets the one refusal text.
func TestLocalPathError_Mapping(t *testing.T) {
	const p = "/srv/vulture/sources/app"
	notExist := &fs.PathError{Op: "statat", Path: "app", Err: syscall.ENOENT}
	denied := &fs.PathError{Op: "statat", Path: "app", Err: syscall.EACCES}
	for _, c := range []struct {
		name     string
		err      error
		confined bool
		want     string
	}{
		{"disabled", pathutil.ErrLocalSourcesDisabled, false, localDisabledText},
		{"disabled wins", fmt.Errorf("%w: %w", pathutil.ErrLocalSourcesDisabled, pathutil.ErrNotPermitted), true, localDisabledText},
		{"not permitted", fmt.Errorf("%w: path escapes source root", pathutil.ErrNotPermitted), true, localNotPermittedText},
		{"not permitted in local mode", pathutil.ErrNotPermitted, false, localNotPermittedText},
		{"not permitted wins over missing", fmt.Errorf("%w: %w", pathutil.ErrNotPermitted, notExist), true, localNotPermittedText},
		{"missing, confined", notExist, true, "path does not exist: " + p},
		{"missing, local mode", notExist, false, "path does not exist: " + p},
		{"unreadable", denied, true, "path is not readable by the server: " + p},
		{"not a directory", pathutil.ErrNotDir, false, "path is not a directory: " + p},
		{"unrecognised, confined", errors.New("statat app: path escapes from parent"), true, localNotPermittedText},
		{"unrecognised, local mode", errors.New("stat: input/output error"), false, "validate path: stat: input/output error"},
	} {
		if got := localPathError(p, c.err, c.confined); got == nil || got.Error() != c.want {
			t.Errorf("%s: localPathError = %v; want %q", c.name, got, c.want)
		}
	}
}
