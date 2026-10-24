package api

func h(c *gin.Context) {
	if err := run(); err != nil {
		c.JSON(500, gin.H{"error": scrubbedMessage(err)}) // EXPECT: clean sq-go-scrubbed-qualifier
	}
}
