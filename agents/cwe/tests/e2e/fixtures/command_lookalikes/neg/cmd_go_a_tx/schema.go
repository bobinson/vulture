package m

type Svc struct{}

func (s *Svc) Begin() (*Svc, error) { return s, nil }
func (s *Svc) Exec(q string)        {}

func Mk(s *Svc, name string) {
	tx, _ := s.Begin()
	tx.Exec("CREATE TABLE " + name) // EXPECT: clean
}
