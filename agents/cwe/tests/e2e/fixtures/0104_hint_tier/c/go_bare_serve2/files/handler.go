package files

import (
	"net/http"
	"path/filepath"
)

func (s *Store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	p := filepath.Join(s.Root, name)
	if !s.Exists(p) {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, p)
}
