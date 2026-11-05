package api

func publicMessage(err error) string {
	return err.Error()
}

func h(c *gin.Context) {
	if err := repo.Save(c); err != nil {
		c.JSON(500, gin.H{"error": publicMessage(err)}) // EXPECT: finding tp-go-defined-public-renders
	}
}
