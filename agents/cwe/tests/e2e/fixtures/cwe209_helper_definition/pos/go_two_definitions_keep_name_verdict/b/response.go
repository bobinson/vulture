package b

import (
	"fmt"
	"net/http"
)

func writeInternalError(w http.ResponseWriter, r *http.Request, op string, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, op, err)
}
