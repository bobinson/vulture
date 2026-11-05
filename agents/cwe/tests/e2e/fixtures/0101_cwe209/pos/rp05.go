func h(c *gin.Context) {
	rows, err := db.Query(q)
	if err != nil {
		// EXPECT-NEXT: finding
		c.JSON(500, gin.H{"error": err})
	}
}
