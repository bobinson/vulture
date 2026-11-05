package keyfile

import (
	"fmt"
	"os"
)

// writeKey writes pem to a private file and returns its path and a cleanup.
// The handle is closed on every path, the last one well below the open.
func writeKey(dir, pem string) (string, func(), error) {
	// EXPECT-NEXT: clean
	tmp, err := os.CreateTemp(dir, "key-*")
	if err != nil {
		return "", nil, fmt.Errorf("create key file: %w", err)
	}
	path := tmp.Name()
	cleanup := func() { os.Remove(path) }

	if err := os.Chmod(path, 0o600); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("chmod key file: %w", err)
	}
	if _, err := tmp.WriteString(pem); err != nil {
		tmp.Close()
		cleanup()
		return "", nil, fmt.Errorf("write key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("finish key file: %w", err)
	}
	return path, cleanup, nil
}
