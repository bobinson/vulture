package cache

// Entry is one cached value.
type Entry struct {
	Name    string
	Expires int64
}

// Cache answers lookups with the comma-ok idiom.
type Cache interface {
	Lookup(key string) (*Entry, bool)
}

// nameOf exits when the lookup missed, then reads the entry.
func nameOf(c Cache, key string) string {
	// EXPECT-NEXT: clean
	e, ok := c.Lookup(key)
	if !ok {
		return ""
	}
	return e.Name
}

// stale short-circuits on a miss before reading the entry.
func stale(c Cache, key string, now int64) bool {
	// EXPECT-NEXT: clean
	e, ok := c.Lookup(key)
	return !ok || e.Expires < now
}

// label reads the entry only when the lookup hit.
func label(c Cache, key string) string {
	// EXPECT-NEXT: clean
	e, found := c.Lookup(key)
	if found && e.Name != "" {
		return e.Name
	}
	return key
}
