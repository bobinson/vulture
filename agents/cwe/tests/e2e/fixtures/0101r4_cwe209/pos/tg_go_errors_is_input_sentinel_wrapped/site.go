package api

// errors.Is only proves the CHAIN holds the sentinel: err.Error() is the whole
// wrapped chain, so its text is whatever context the wrappers added.
func h(c *gin.Context) {
	if err := repo.Find(c); err != nil {
		if errors.Is(err, ErrInvalidInput) {
			c.JSON(400, gin.H{"error": err.Error()}) // EXPECT: finding tp-go-errors-is-input-still-wrapped
			return
		}
	}
}
