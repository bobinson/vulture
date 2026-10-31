using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading.Tasks;

class Pump {
    void Inbox(BlockingCollection<string> inbox) {
        var all = new List<string>();
        foreach (var m in inbox.GetConsumingEnumerable()) {
            // EXPECT-NEXT: finding foreach over a consuming queue keeps every message
            all.Add(m);
        }
    }

    async Task Stream(IAsyncEnumerable<string> stream) {
        var all = new List<string>();
        await foreach (var m in stream) {
            // EXPECT-NEXT: finding await foreach over a stream keeps every message
            all.Add(m);
        }
    }

    void Lines(TcpClient client) {
        var reader = new StreamReader(client.GetStream());
        var all = new List<string>();
        foreach (var line in ReadLines(reader)) {
            // EXPECT-NEXT: finding foreach over lines read from a socket
            all.Add(line);
        }
    }

    void Fixed(List<string> names) {
        var all = new List<string>();
        foreach (var n in names) {
            // EXPECT-NEXT: clean foreach over an in-memory list
            all.Add(n);
        }
    }

    IEnumerable<string> ReadLines(StreamReader r) { yield break; }
}
