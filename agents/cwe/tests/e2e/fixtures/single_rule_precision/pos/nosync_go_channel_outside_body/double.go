package double

// double writes results from goroutines that synchronise with nothing; the
// channel receive below is outside their bodies and orders none of the writes.
func double(jobs []int, results []int) {
	for _, j := range jobs {
		// EXPECT-NEXT: finding
		go func(j int) {
			results[j] = j * 2
		}(j)
	}
	done := make(chan struct{})
	close(done)
	<-done
}
