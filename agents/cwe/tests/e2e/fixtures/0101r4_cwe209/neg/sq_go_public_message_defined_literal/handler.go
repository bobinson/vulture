package api

func publicMessage(err error) string {
	return "internal error"
}

func h(c *gin.Context) {
	if err := repo.Save(c); err != nil {
		c.JSON(500, gin.H{"error": publicMessage(err)}) // EXPECT: clean sq-go-defined-public-literal
	}
}
