package write

import "os"

// save closes the file only when the write fails; on success it stays open.
func save(p string, b []byte) error {
	// EXPECT-NEXT: finding
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return nil
}
