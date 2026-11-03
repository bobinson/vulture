package handler

import (
	"fmt"
	"io"
	"net/http"
)

type counter struct{ n int }

// Fprint shares its name with fmt.Fprint and writes nothing: the call below is fmt's.
func (c *counter) Fprint(w io.Writer, v any) { c.n++ }

func writeErrorText(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, err)
}
