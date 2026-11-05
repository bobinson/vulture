package leak

import (
	"log"
	"os"
)

// head reads the first bytes of p; a comment that mentions closing closes nothing.
func head(p string) ([]byte, error) {
	// EXPECT-NEXT: finding
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	// TODO: f.Close() is never called
	buf := make([]byte, 64)
	n, err := f.Read(buf)
	return buf[:n], err
}

// tail logs a reminder instead of closing.
func tail(p string) (*os.File, error) {
	// EXPECT-NEXT: finding
	g, err := os.Open(p)
	log.Println("remember to call g.Close()")
	return g, err
}
