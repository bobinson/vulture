package fileutil

import (
	"context"
	"os"
	"path/filepath"

	"github.com/vulture/backend/pkg/scanignore"
)

// CountFiles walks root and returns the total count of regular files,
// skipping the version-control stores and the folders of the scanner's
// default ignore file (pkg/scanignore). Uses a background context.
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
		if d.IsDir() && skipped(d.Name()) {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			count++
		}
		return nil
	})
	return count, err
}

// skipped reports whether a directory called name is left out of the count:
// a version-control store, or a folder of the default ignore file.
func skipped(name string) bool {
	return scanignore.VCS(name) || scanignore.Default(name)
}
