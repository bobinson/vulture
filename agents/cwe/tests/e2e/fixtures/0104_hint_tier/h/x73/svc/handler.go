package svc

import (
	"net/http"
	"path/filepath"
)

const root = "/srv/files"

func Files(w http.ResponseWriter, r *http.Request) {
	f, err := open( // EXPECT: clean check=cwe.input_validation.path_traversal
		filepath.Join(root, r.FormValue("name")), // EXPECT: finding check=cwe.input_validation.external_path_control
	)
	if err != nil {
		return
	}
	defer f.Close()
}
