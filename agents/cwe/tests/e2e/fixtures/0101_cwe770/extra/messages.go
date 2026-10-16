package relay

import "sync/atomic"

type Message struct{ Body string }
type Request struct{ Messages []Message }

func Bodies(req *Request) []string {
	var out []string
	for _, m := range req.Messages {
		// EXPECT-NEXT: clean range over a slice already decoded into memory
		out = append(out, m.Body)
	}
	return out
}

type Conn interface{ Read(p []byte) (int, error) }

func Tally(conn Conn) int64 {
	octetsSeen := atomic.Int64{}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return octetsSeen.Load()
		}
		// EXPECT-NEXT: clean atomic counter Add, not allocation
		octetsSeen.Add(int64(n))
	}
}

var octetsTotal atomic.Int64

func TallyShared(conn Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		// EXPECT-NEXT: clean package-level counter (name carries a counter word)
		octetsTotal.Add(int64(n))
	}
}

var octetsSeenShared atomic.Int64

func TallyField(conn Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		// EXPECT-NEXT: clean an Add of a numeric conversion is arithmetic wherever the atomic is declared (R770-IMPL-3)
		octetsSeenShared.Add(int64(n))
	}
}
