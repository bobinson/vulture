// pins: 0104 WS-C - Go is outside the rule: a locate helper stats a path joined from its argument (positive)
package files

import (
	"os"
	"path/filepath"
)

type Store struct{ Root string }

func (s *Store) Locate(fileName string) (string, error) {
	p := filepath.Join(s.Root, fileName)
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}
