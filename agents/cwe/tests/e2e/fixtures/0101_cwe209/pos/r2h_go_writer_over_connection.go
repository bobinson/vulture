package ledger

import (
	"bufio"
	"net"
)

func relayFault(conn net.Conn, err error) {
	w := bufio.NewWriter(conn)
	// EXPECT-NEXT: finding
	w.WriteString(err.Error())
	w.Flush()
}
