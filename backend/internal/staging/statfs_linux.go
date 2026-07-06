//go:build linux

package staging

import "syscall"

// freeBytes reports the bytes available to unprivileged users on the
// filesystem containing path (statfs f_bavail × f_bsize). No new deps:
// stdlib syscall only (LLD P0d).
func freeBytes(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * st.Bsize, nil
}
