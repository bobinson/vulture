package labels

// Entry is one registry row, held by value.
type Entry struct {
	Name string
	Tier string
}

// Registry hands out entries by value.
type Registry interface {
	Entry(name string) Entry
}

// labels returns the label of each named entry; e is only passed on.
func labels(reg Registry, names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		// EXPECT-NEXT: clean
		e := reg.Entry(n)
		out = append(out, label(e))
	}
	return out
}

func label(e Entry) string {
	return e.Name + ":" + e.Tier
}
