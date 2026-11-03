package csrf

import "net/http"

// CSRFHeader is the header the single-page app sends.
const CSRFHeader = "X-App-CSRF"

func hasCSRFHeader(r *http.Request) bool { return r.Header.Get(CSRFHeader) != "" } // EXPECT: clean
