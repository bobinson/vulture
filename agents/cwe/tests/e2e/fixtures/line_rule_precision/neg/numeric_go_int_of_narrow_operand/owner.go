package owner

import (
	"os"
	"syscall"
)

// ownedByMe reports whether the directory belongs to the running user.
func ownedByMe(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	uid := st.Uid
	return ok && int(uid) == os.Getuid() && info.IsDir() // EXPECT: clean
}
