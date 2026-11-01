//go:build unix

package fileutil

import (
	"io/fs"
	"syscall"
)

// OwnerOf returns the owning uid and the hard-link count recorded in fi,
// which must come from the os package (Stat, Lstat, a DirEntry's Info). ok is
// false when fi carries no stat record, so a caller deciding on ownership
// fails closed.
func OwnerOf(fi fs.FileInfo) (uid uint32, nlink uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	// Nlink is uint16 or uint32 on some unix platforms, uint64 on others.
	return st.Uid, uint64(st.Nlink), true
}
