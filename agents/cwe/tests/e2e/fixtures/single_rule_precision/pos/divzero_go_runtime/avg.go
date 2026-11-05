package avg

// mean divides by a caller-supplied count.
func mean(xs []int, count int) int {
	sum := 0
	for _, x := range xs {
		sum += x
	}
	// EXPECT-NEXT: finding
	return sum / count
}

// A var group is initialised when the program starts, not by the compiler.
var (
	jobs    = 120
	workers = load()
	// EXPECT-NEXT: finding
	perWorker = jobs / workers
)

func load() int { return 0 }
