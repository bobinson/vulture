package api

func load(id string) (Outcome, error) {
	if err := db.Touch(id); err != nil {
		return Outcome{}, NewAppError("E_DB", err)
	}
	return remote.Lookup(id), nil
}

func Handler(c *gin.Context) {
	out, err := load(c.Query("id"))
	if err != nil {
		c.JSON(500, gin.H{"error": "internal"})
		return
	}
	c.JSON(200, gin.H{"error": out.Error}) // EXPECT: clean clean-Q-second-return
}
