// Pins: exec.Command("ls", dir).Output() with dir external; argv form with no shell, so no command row (argument injection stays a separate CWE).
package app

func dirListing(c *gin.Context) ([]byte, error) {
	dir := c.Query("dir")
	return exec.Command("ls", dir).Output()
}
