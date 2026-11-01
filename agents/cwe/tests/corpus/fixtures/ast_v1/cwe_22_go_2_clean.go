// Pins: an early-return guard `if !strings.HasPrefix(full, rootDir+"/") { return }` on the same name before os.Open(full).
package app

const rootDir = "/srv/docs"

func pickDoc(c *gin.Context) (*os.File, error) {
	full := filepath.Join(rootDir, c.Query("f"))
	if !strings.HasPrefix(full, rootDir+"/") {
		return nil, os.ErrPermission
	}
	return os.Open(full)
}
