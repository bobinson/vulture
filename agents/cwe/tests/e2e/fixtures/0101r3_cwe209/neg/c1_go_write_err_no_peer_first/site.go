package worker

func (j *Job) Run() {
	if err := j.step(); err != nil {
		writeErr(j.log, err.Error()) // EXPECT: clean first-argument-not-a-peer
	}
}
