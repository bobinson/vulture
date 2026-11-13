package svc

import (
	"io/ioutil"
	"net/http"
	"os"
)

func Files(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("p")
	f, _ := os.Open(name) // EXPECT: finding check=cwe.input_validation.path_traversal
	defer f.Close()
	b1, _ := os.ReadFile(name) // EXPECT: finding check=cwe.input_validation.path_traversal
	b2, _ := ioutil.ReadFile(name) // EXPECT: finding check=cwe.input_validation.path_traversal
	os.Remove(name) // EXPECT: finding check=cwe.input_validation.path_traversal
	w.Write(append(b1, b2...))
}
