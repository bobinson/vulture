package cache

import "log"

// Entry is one cached value.
type Entry struct{ Value int }

// Cache answers lookups with the comma-ok idiom.
type Cache interface {
	Lookup(key string) (*Entry, bool)
}

// positive tests ok only for a log line; the use below runs either way.
func positive(c Cache, k string, debug bool) int {
	// EXPECT-NEXT: finding
	e, ok := c.Lookup(k)
	if ok && debug {
		log.Printf("hit %s", k)
	}
	return e.Value
}

// fallsThrough tests !ok but does not leave the routine when it holds.
func fallsThrough(c Cache, k string) int {
	// EXPECT-NEXT: finding
	e, ok := c.Lookup(k)
	if !ok || k == "" {
		log.Printf("miss %s", k)
	}
	return e.Value
}

// nestedExit leaves only when verbose is set too.
func nestedExit(c Cache, k string, verbose bool) int {
	// EXPECT-NEXT: finding
	e, ok := c.Lookup(k)
	if !ok {
		if verbose {
			return 0
		}
		log.Printf("miss %s", k)
	}
	return e.Value
}
