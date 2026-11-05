package cache

// Entry is one cached value.
type Entry struct{ Name string }

// Cache answers lookups with the comma-ok idiom.
type Cache interface {
	Lookup(key string) (*Entry, bool)
}

// nameOf reads the entry BEFORE it tests whether the lookup hit.
func nameOf(c Cache, key string) string {
	// EXPECT-NEXT: finding
	e, ok := c.Lookup(key)
	name := e.Name
	if !ok {
		return ""
	}
	return name
}

// first tests ok but does not leave when it is false.
func first(c Cache, key string) string {
	// EXPECT-NEXT: finding
	e, ok := c.Lookup(key)
	if !ok {
		key = "missing"
	}
	return e.Name + key
}
