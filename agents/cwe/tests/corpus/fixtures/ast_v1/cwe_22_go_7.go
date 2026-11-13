// pins: 0104 WS-C - Go is outside the rule: a concatenated path reaches os.Stat (positive)
package files

import "os"

type Store struct{ Root string }

func (s *Store) Locate(fileName string) (string, error) {
	p := s.Root + "/" + fileName
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}
