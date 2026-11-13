package files

import (
	"net/http"
	"path/filepath"
)

func (s *Store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(s.Root, r.URL.Query().Get("name")) // EXPECT: finding check=cwe.input_validation.external_path_control
	if !s.Exists(p) {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, p)
}
