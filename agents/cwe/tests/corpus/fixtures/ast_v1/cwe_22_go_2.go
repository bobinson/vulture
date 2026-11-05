// Pins: os.Open(full) where full := filepath.Join(rootDir, c.Query("f")) and c is a *gin.Context param (accessor on a context-typed param).
package app

const rootDir = "/srv/docs"

func pickDoc(c *gin.Context) (*os.File, error) {
	full := filepath.Join(rootDir, c.Query("f"))
	return os.Open(full)
}
