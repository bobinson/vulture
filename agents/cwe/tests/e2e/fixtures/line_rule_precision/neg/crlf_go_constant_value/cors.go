package cors

import (
	"net/http"

	"example.com/app/requestid"
)

func expose(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Expose-Headers", requestid.Header) // EXPECT: clean
}
