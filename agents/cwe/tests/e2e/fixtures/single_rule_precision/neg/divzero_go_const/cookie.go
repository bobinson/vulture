package cookie

import "time"

// SessionTTL is how long a session lasts.
const SessionTTL = 24 * time.Hour

const (
	maxItems  = 120
	pageCount = 12
)

// Constant expressions are evaluated by the compiler; a zero divisor there
// fails the build, never a request.
const (
	// cookieName is the session cookie's name.
	cookieName = "app_session"
	// sessionMaxAge is the cookie's lifetime in seconds.
	// EXPECT-NEXT: clean
	sessionMaxAge = int(SessionTTL / time.Second)
	// EXPECT-NEXT: clean
	bucketWidth uint64 = maxItems / pageCount
)

// EXPECT-NEXT: clean
const perPage = maxItems / pageCount
