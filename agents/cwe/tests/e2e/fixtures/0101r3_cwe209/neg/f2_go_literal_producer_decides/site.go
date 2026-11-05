package api

type Check struct {
	OK    bool
	Error string
}

func validate(name string) Check {
	if name == "" {
		return Check{OK: false, Error: "name is required"}
	}
	return Check{OK: true}
}

func Create(c *Context) {
	job := &Job{}
	if err := save(c); err != nil {
		job.Error = err.Error()
		jobs.Store(job)
	}
	v := validate(c.Query("name"))
	if !v.OK {
		c.JSON(400, map[string]string{"error": v.Error}) // EXPECT: clean literal-producer-decides
	}
}
