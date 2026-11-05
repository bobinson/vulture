package registry

// Plugin is one registry entry, held by value.
type Plugin struct {
	Source string
	Tier   string
}

// Registry looks plugins up by name.
type Registry interface {
	ByName(name string) (Plugin, bool)
}

func builtin(name string) bool { return name == "core" }

// inTree decides "in-tree" from the registry when there is one. The lookup's
// ok result is tested before p is used, and p is only passed on.
func inTree(reg Registry) func(string) bool {
	if reg == nil {
		return builtin
	}
	return func(name string) bool {
		// EXPECT-NEXT: clean
		p, ok := reg.ByName(name)
		if !ok {
			return builtin(name)
		}
		return isVirtual(p)
	}
}

// isVirtual reports whether p is the registry's synthesised entry.
func isVirtual(p Plugin) bool {
	return p.Source == "virtual" && p.Tier == "in-tree"
}
