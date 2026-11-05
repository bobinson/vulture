package p

type Outcome struct {
	OK    bool
	Error string
}

func (s *Svc) load(id string) Outcome {
	if _, err := s.db.Get(id); err != nil {
		return Outcome{false, err.Error()}
	}
	return Outcome{OK: true}
}

func (s *Svc) Handler(c *gin.Context) {
	out := s.load(c.Query("id"))
	c.JSON(500, gin.H{"error": out.Error}) // EXPECT: finding tp-go-method-producer
}
