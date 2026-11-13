package svc

import (
	"net/http"
	"os"
	"path/filepath"
)

func Shelf(w http.ResponseWriter, r *http.Request) {
	hash := filepath.Join
	data, _ := os.ReadFile(hash("/srv/shelf", r.FormValue("n"))) // EXPECT: finding check=cwe.input_validation.path_traversal
	w.Write(data)
}
