package pathutil

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
)

// The local-path policy's two path checks (feature 0102): ResolveDir answers
// an ingest (the path must be an existing directory, confined when a root is
// set), Recheck answers a dispatch of a stored path (confined when a root is
// set, but it need not exist). Both gate through Allow first.

// localSourcesCase is one policy check and the error it must match (nil:
// accepted).
type localSourcesCase struct {
	name   string
	policy LocalSources
	path   string
	want   error
}

func TestLocalSources_Recheck_Table(t *testing.T) {
	tr := newConfineTree(t)
	project := confineMkdir(t, filepath.Join(tr.root, "project"))
	escape := confineSymlink(t, tr.outside, filepath.Join(tr.root, "escape"))
	local := NewLocalSources("", true, false)
	rooted := NewLocalSources(tr.root, false, false)
	for _, c := range []localSourcesCase{
		{"centralized without a root", NewLocalSources("", false, false), project, ErrLocalSourcesDisabled},
		{"read-only with a root", NewLocalSources(tr.root, false, true), project, ErrLocalSourcesDisabled},
		{"local mode, any directory", local, tr.outside, nil},
		{"local mode, missing", local, filepath.Join(tr.outside, "missing"), nil},
		{"local mode, relative", local, "relative/path", nil},
		{"root, inside", rooted, project, nil},
		{"root, inside but no longer there", rooted, filepath.Join(tr.root, "gone"), nil},
		{"root, outside", rooted, tr.outside, ErrNotPermitted},
		{"root, in-root link out", rooted, escape, ErrNotPermitted},
		{"root, dot-dot spelling", rooted, tr.root + "/project/../project", ErrNotPermitted},
		{"root, relative", rooted, "project", ErrNotPermitted},
	} {
		wantErrIs(t, c.name, c.policy.Recheck(c.path), c.want)
	}
}

func TestLocalSources_ResolveDir_Table(t *testing.T) {
	tr := newConfineTree(t)
	project := confineMkdir(t, filepath.Join(tr.root, "project"))
	file := confineFile(t, filepath.Join(tr.root, "notes.txt"))
	gone := filepath.Join(tr.root, "gone")
	local := NewLocalSources("", true, false)
	rooted := NewLocalSources(tr.root, false, false)
	for _, c := range []localSourcesCase{
		{"centralized without a root, existing dir", NewLocalSources("", false, false), project, ErrLocalSourcesDisabled},
		{"local mode, dir", local, tr.outside, nil},
		{"local mode, file", local, file, ErrNotDir},
		{"local mode, missing", local, gone, fs.ErrNotExist},
		{"root, inside dir", rooted, project, nil},
		{"root, inside file", rooted, file, ErrNotDir},
		{"root, inside missing", rooted, gone, fs.ErrNotExist},
		{"root, outside dir", rooted, tr.outside, ErrNotPermitted},
		{"root that does not exist", NewLocalSources(gone, false, false), filepath.Join(gone, "x"), ErrNotPermitted},
	} {
		wantErrIs(t, c.name, c.policy.ResolveDir(c.path), c.want)
	}
	// A root that does not resolve is the path's refusal, never its absence.
	if err := NewLocalSources(gone, false, false).ResolveDir(filepath.Join(gone, "x")); errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ResolveDir under a missing root = %v; must not read as the path not existing", err)
	}
}
