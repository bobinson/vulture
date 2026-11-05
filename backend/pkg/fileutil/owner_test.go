//go:build unix

package fileutil

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestOwnerOf_Unix: OwnerOf reads the owning uid and the hard-link count
// from a FileInfo the os package produced, and answers ok=false (so a caller
// fails closed) for one it cannot read them from.
func TestOwnerOf_Unix(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ownerOfWant(t, file, 1)
	if err := os.Link(file, filepath.Join(dir, "g")); err != nil {
		t.Fatal(err)
	}
	ownerOfWant(t, file, 2)
	if _, _, ok := OwnerOf(ownerOfNoStat{}); ok {
		t.Error("OwnerOf(a FileInfo without a stat record) answered ok=true, want false")
	}
}

func ownerOfWant(t *testing.T, path string, nlink uint64) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	uid, n, ok := OwnerOf(fi)
	if want := (ownerOfResult{uint32(os.Geteuid()), nlink, true}); (ownerOfResult{uid, n, ok}) != want {
		t.Errorf("OwnerOf(%s) = (%d, %d, %v), want %+v", path, uid, n, ok, want)
	}
}

type ownerOfResult struct {
	uid   uint32
	nlink uint64
	ok    bool
}

// ownerOfNoStat is a FileInfo whose Sys() carries no stat record.
type ownerOfNoStat struct{}

func (ownerOfNoStat) Name() string       { return "no-stat" }
func (ownerOfNoStat) Size() int64        { return 0 }
func (ownerOfNoStat) Mode() fs.FileMode  { return 0 }
func (ownerOfNoStat) ModTime() time.Time { return time.Time{} }
func (ownerOfNoStat) IsDir() bool        { return false }
func (ownerOfNoStat) Sys() any           { return nil }
