package fanout

import "sync"

// fetchAll fetches every url concurrently; each goroutine writes its own slot
// and the WaitGroup orders those writes before the read of sizes.
func fetchAll(urls []string, fetch func(string) int) []int {
	sizes := make([]int, len(urls))
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		// EXPECT-NEXT: clean
		go func(i int, u string) {
			defer wg.Done()
			sizes[i] = fetch(u)
		}(i, u)
	}
	wg.Wait()
	return sizes
}
