package count

// total adds the lengths from several goroutines into one captured variable
// with no lock and no channel.
func total(items []string) int {
	n := 0
	for _, it := range items {
		// EXPECT-NEXT: finding
		go func(s string) {
			n += len(s)
		}(it)
	}
	return n
}
