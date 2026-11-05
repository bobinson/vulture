package relay

import "net/http"

func writeFault(w http.ResponseWriter, problem error) {
	// EXPECT-NEXT: clean  known-gap a parameter that is not error-named is clean whatever its declared type (LLD 5.3.4, R-C7)
	w.Write([]byte(problem.Error()))
}
