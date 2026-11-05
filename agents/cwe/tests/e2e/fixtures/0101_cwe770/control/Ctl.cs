using System.Collections.Generic;
using System.Net.Sockets;

public class Ctl {
    public List<byte[]> Drain(NetworkStream stream) {
        var chunks = new List<byte[]>();
        while (true) {
            var buf = new byte[4096];
            int n = stream.Read(buf, 0, buf.Length);
            if (n == 0) break;
            // EXPECT-NEXT: finding C19 control for E19 (K&R braces)
            chunks.Add(buf);
        }
        return chunks;
    }
}
