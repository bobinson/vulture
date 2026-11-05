using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;

class Counters {
    long received;
    void Run(Socket sock) {
        var buf = new byte[1024];
        int n;
        while ((n = sock.Receive(buf)) > 0) {
            // EXPECT-NEXT: clean interlocked arithmetic
            Interlocked.Add(ref received, n);
        }
    }
    List<byte[]> Keep(Socket sock) {
        var frames = new List<byte[]>();
        var buf = new byte[1024];
        while (sock.Receive(buf) > 0) {
            // EXPECT-NEXT: finding every frame retained
            frames.Add((byte[])buf.Clone());
        }
        return frames;
    }
}
