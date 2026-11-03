package prefix

import (
	"os"
	"path/filepath"
	"sort"
)

// deepestExisting resolves the deepest existing prefix of abs. Go checks every
// index at run time: a bad one panics, it never reads past the slice.
func deepestExisting(abs string, ends []int) (string, error) {
	n := 1 + sort.Search(len(ends)-1, func(i int) bool {
		// EXPECT-NEXT: clean
		_, err := os.Lstat(abs[:ends[i+1]])
		return err != nil
	})
	// EXPECT-NEXT: clean
	head, err := filepath.EvalSymlinks(abs[:ends[n-1]])
	if err != nil {
		return "", err
	}
	// EXPECT-NEXT: clean
	return filepath.Join(head, abs[ends[n-1]:]), nil
}
