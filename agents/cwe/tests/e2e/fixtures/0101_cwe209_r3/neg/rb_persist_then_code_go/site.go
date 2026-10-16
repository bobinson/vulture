package api

func runJob(id string) Outcome {
	if err := work(id); err != nil {
		store.Save(Job{ID: id, Error: err.Error()})
		return Outcome{OK: false, Error: "JOB_FAILED"}
	}
	return Outcome{OK: true}
}

func Handler(c *gin.Context) {
	out := runJob(c.Query("id"))
	c.JSON(500, gin.H{"error": out.Error}) // EXPECT: clean clean-persisted-go
}
