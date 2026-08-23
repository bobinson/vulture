package hostkeys

import (
	"os"
	"path/filepath"
)

func knownHostsDir() (string, error) {
	dir, err := os.MkdirTemp(os.TempDir(), "app-ssh-")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "known_hosts"), nil
}
