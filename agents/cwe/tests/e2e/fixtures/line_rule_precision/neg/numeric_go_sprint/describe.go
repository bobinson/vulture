package describe

import "fmt"

// Describe renders an error for the log.
func Describe(err error) string {
	cause := fmt.Sprint(err) // EXPECT: clean
	return "op: " + cause
}
