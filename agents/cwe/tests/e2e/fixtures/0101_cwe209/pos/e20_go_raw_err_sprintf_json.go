func h(c *gin.Context) {
	if err := run(); err != nil {
		// EXPECT-NEXT: finding  go raw err sprintf json
		c.JSON(500, gin.H{"error": fmt.Sprintf("%v", err)})
	}
}
