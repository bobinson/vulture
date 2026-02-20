package fileutil

import (
	"os"
	"path/filepath"
)

var defaultIgnore = map[string]bool{
	".git":         true,
	"node_modules": true,
	".DS_Store":    true,
	"__pycache__":  true,
	".venv":        true,
	"vendor":       true,
}

func CountFiles(root string) (int, error) {
	count := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && defaultIgnore[d.Name()] {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			count++
		}
		return nil
	})
	return count, err
}
