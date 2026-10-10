//go:build !unix

package reveal

// ownedRoot: no ownership model to check on this platform.
func ownedRoot(string) bool { return true }
