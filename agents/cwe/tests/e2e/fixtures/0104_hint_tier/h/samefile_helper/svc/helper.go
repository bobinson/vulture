package svc

import (
	"net/http"
	"os"
)

func load(p string) ([]byte, error) {
	return os.ReadFile(p) // EXPECT: finding check=cwe.input_validation.path_traversal
}

func open(p string) (*os.File, error) {
	return os.Open(p) // EXPECT: finding check=cwe.input_validation.path_traversal
}

func remove(p string) error {
	return os.Remove(p) // EXPECT: finding check=cwe.input_validation.path_traversal
}

func Handle(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("p")
	load(name)
	open(name)
	remove(name)
}
