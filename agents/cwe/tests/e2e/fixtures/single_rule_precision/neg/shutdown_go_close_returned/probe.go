package probe

import "os"

// openable reports whether dir can be opened as a root. The handle is closed
// by the return statement, so its close error reaches the caller.
func openable(dir string) error {
	// EXPECT-NEXT: clean
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	return r.Close()
}
