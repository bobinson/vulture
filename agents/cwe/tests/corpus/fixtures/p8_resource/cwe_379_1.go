package hostkeys

import (
	"os"
	"path/filepath"
)

func knownHostsDir() string {
	dir := filepath.Join(os.TempDir(), "app-ssh")
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, "known_hosts")
}
