package fileutil

import (
	"context"
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

// CountFiles walks root and returns the total count of regular files,
// skipping defaultIgnore directories. Uses a background context.
func CountFiles(root string) (int, error) {
	return CountFilesCtx(context.Background(), root)
}

// CountFilesCtx is the context-aware variant of CountFiles. The walk
// honours ctx cancellation: if the caller cancels (e.g. HTTP client
// disconnects, request deadline exceeded), the walk aborts with the
// context error rather than running to completion. Important for
// large-monorepo cases where the walk would otherwise pin a request
// goroutine for seconds.
func CountFilesCtx(ctx context.Context, root string) (int, error) {
	count := 0
	err := filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Cheap context check at every dir entry. Cost is one
		// non-blocking select per file — negligible vs. the syscall.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
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
