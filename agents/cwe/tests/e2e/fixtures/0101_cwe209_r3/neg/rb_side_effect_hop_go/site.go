package api

func record(id string) {
	if err := db.Touch(id); err != nil {
		metrics.Add(fmt.Sprint(err))
	}
}

func process(id string) Result {
	record(id)
	return remote.Do(id)
}

func Handler(c *gin.Context) {
	out := process(c.Query("id"))
	c.JSON(502, gin.H{"error": out.Error}) // EXPECT: clean clean-hop-go
}
