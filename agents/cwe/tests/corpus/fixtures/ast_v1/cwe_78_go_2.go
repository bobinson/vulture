// Pins: exec.Command("sh", "-c", "ls "+dir).Output() where dir := c.Query("dir") on a *gin.Context param (shell flag + concatenation).
package app

func dirListing(c *gin.Context) ([]byte, error) {
	dir := c.Query("dir")
	return exec.Command("sh", "-c", "ls "+dir).Output()
}
