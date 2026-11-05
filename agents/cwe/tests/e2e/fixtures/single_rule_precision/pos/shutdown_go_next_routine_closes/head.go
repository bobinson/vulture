package head

import (
	"bufio"
	"io"
	"os"
)

// reader opens p and never closes it; the Close below belongs to release.
func reader(p string) (*bufio.Reader, error) {
	// EXPECT-NEXT: finding
	f, err := os.Open(p)
	return bufio.NewReader(f), err
}

func release(c io.Closer) error { return c.Close() }
