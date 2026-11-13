package svc

import (
	"io"
	"net/http"
	"path/filepath"
	"strings"
)

func Blob(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll( // EXPECT: clean check=cwe.input_validation.path_traversal
		strings.NewReader(filepath.Join("/srv/blobs", r.FormValue("name"))), // EXPECT: finding check=cwe.input_validation.external_path_control
	)
	w.Write(data)
}
