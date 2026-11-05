package handler

import (
	"fmt"
	"net/http"
)

func writeErrorFormat(w http.ResponseWriter, format string, args ...any) {
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, format, args...)
}
