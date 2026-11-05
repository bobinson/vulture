package lookup

// User is one stored account.
type User struct{ Name string }

// Store finds users; a miss returns a nil user.
type Store interface {
	Find(id string) (*User, error)
}

// nameOf discards the error and dereferences the result anyway.
func nameOf(s Store, id string) string {
	// EXPECT-NEXT: finding
	u, _ := s.Find(id)
	return u.Name
}

// greet never checks the error before reading the user.
func greet(s Store, id string) string {
	// EXPECT-NEXT: finding
	u, err := s.Find(id)
	msg := "hello " + u.Name
	_ = err
	return msg
}
