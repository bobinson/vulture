//go:build unix

package reveal

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vulture/backend/pkg/fileutil"
)

// ownedRoot refuses a git clone root under the shared temp staging tree that
// this process's user does not own: on a shared host another user could have
// created the predictable directory first and planted links in it. Any other
// root (a local source path, a container mount) is the operator's own.
func ownedRoot(root string) bool {
	staging := filepath.Join(os.TempDir(), "vulture-sources")
	if !strings.HasPrefix(filepath.Clean(root)+"/", staging+"/") {
		return true
	}
	info, err := os.Lstat(staging)
	if err != nil {
		return false
	}
	uid, _, ok := fileutil.OwnerOf(info)
	return ok && int(uid) == os.Getuid() && info.IsDir()
}
