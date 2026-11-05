package size

import "os"

// size returns the size of the file at p. The handle is never closed.
func size(p string) (int64, error) {
	// EXPECT-NEXT: finding
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
