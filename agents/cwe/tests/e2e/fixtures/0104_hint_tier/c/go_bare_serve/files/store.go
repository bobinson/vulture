package files

import "os"

type Store struct{ Root string }

// Exists reports whether a stored file is present.
func (s *Store) Exists(filePath string) bool {
	_, err := os.Stat(filePath) // EXPECT: finding check=cwe.input_validation.path_traversal
	return err == nil
}
