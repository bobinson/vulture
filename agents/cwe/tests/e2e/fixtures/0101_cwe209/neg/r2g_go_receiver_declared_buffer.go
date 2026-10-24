package ledger

import "bytes"

func describeFault(err error) string {
	var b bytes.Buffer
	// EXPECT-NEXT: clean  a receiver declared as a buffer in the routine is a local write
	b.WriteString(err.Error())
	return b.String()
}
