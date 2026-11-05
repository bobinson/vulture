//go:build !unix

package fileutil

import "io/fs"

// OwnerOf reports ok=false: this platform has no unix ownership model, so a
// caller deciding on ownership fails closed (or applies its own policy).
func OwnerOf(fs.FileInfo) (uid uint32, nlink uint64, ok bool) { return 0, 0, false }
