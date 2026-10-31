package ws

import "net"

type Conn interface{ ReadMessage() (int, []byte, error) }

func Pump(c Conn) [][]byte {
	var msgs [][]byte
	for {
		_, m, err := c.ReadMessage()
		if err != nil {
			return msgs
		}
		// EXPECT-NEXT: finding E22 ReadMessage/ReadJSON not a pull verb
		msgs = append(msgs, m)
	}
}

var registry []net.Conn

func Serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		// EXPECT-NEXT: finding E22b accept into global (should report)
		registry = append(registry, c)
	}
}

var cache = map[string][]byte{}

func Remember(key string, val []byte) {
	// EXPECT-NEXT: clean known-gap: a global map grown once per call, no loop (NG7) (probe:E23 global map grows per call)
	cache[key] = val
}
