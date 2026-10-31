package api

func h(c *gin.Context) {
	if err := repo.Find(c); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(404, gin.H{"error": err.Error()}) // EXPECT: finding tp-go-errors-is-wrapped-detail
			return
		}
	}
}
