package m

// #include <stdlib.h>
import "C"
import "net/http"

func run(r *http.Request) {
	C.system(C.CString(r.FormValue("c"))) // EXPECT: finding
}
