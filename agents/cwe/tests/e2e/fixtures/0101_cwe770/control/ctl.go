package ws

import "net"

func Pump(c net.Conn) [][]byte {
	var msgs [][]byte
	for {
		buf := make([]byte, 4096)
		_, err := c.Read(buf)
		if err != nil {
			return msgs
		}
		// EXPECT-NEXT: finding C22 control for E22 (Read)
		msgs = append(msgs, buf)
	}
}
