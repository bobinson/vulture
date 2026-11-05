func h(c *gin.Context) {
	if err := run(); err != nil {
		// EXPECT-NEXT: finding  go gin JSON err Error
		c.JSON(500, gin.H{"error": err.Error()})
	}
}
