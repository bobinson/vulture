package producer

// produce streams items to the caller and closes the stream when done.
func produce(items []string) <-chan string {
	out := make(chan string)
	// EXPECT-NEXT: clean
	go func() {
		defer close(out)
		for _, it := range items {
			out <- it
		}
	}()
	return out
}
