package stamp

import (
	"net/http"

	"example.com/app/requestid"
)

func stamp(w http.ResponseWriter, id string) {
	w.Header().Set(requestid.Header, id) // EXPECT: clean
}
