package api

type Outcome struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

func load(id string) Outcome {
	v, err := store.Get(id)
	if err != nil {
		return Outcome{false, err.Error()}
	}
	_ = v
	return Outcome{OK: true}
}

func loadK(id string) Outcome {
	_, err := store.Get(id)
	if err != nil {
		return Outcome{OK: false, Error: err.Error()}
	}
	return Outcome{OK: true}
}

func Handler(c *gin.Context) {
	out := load(c.Query("id"))
	if !out.OK {
		c.JSON(500, gin.H{"error": out.Error}) // EXPECT: finding tp-go-K-positional
		return
	}
	out2 := loadK(c.Query("id"))
	if !out2.OK {
		c.JSON(500, gin.H{"error": out2.Error}) // probe tp-go-F1-keyed
	}
	c.JSON(500, out) // probe tp-go-whole-result
}
