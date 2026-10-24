using System.Collections.Generic;
using System.IO;
using System.Text;

class Flush {
    void Batches(StreamReader r) {
        var batch = new List<string>();
        string line;
        while ((line = r.ReadLine()) != null) {
            // EXPECT-NEXT: clean the batch is flushed and cleared every iteration
            batch.Add(line);
            Send(batch);
            batch.Clear();
        }
    }

    void Assemble(StreamReader r) {
        var sb = new StringBuilder();
        string line;
        while ((line = r.ReadLine()) != null) {
            // EXPECT-NEXT: clean the builder is cleared every iteration
            sb.Append(line);
            Handle(sb.ToString());
            sb.Clear();
        }
    }

    void Chars(StreamReader r) {
        var sb = new StringBuilder();
        int c;
        while ((c = r.Read()) != -1) {
            if (c == '\n') {
                Handle(sb.ToString());
                sb.Clear();
            } else {
                // EXPECT-NEXT: clean the builder is cleared at each newline
                sb.Append((char)c);
            }
        }
    }

    void Window(StreamReader r) {
        var recent = new List<string>();
        string line;
        while ((line = r.ReadLine()) != null) {
            // EXPECT-NEXT: clean the oldest entry is removed every iteration
            recent.Add(line);
            recent.RemoveAt(0);
        }
    }

    void Queue(StreamReader r) {
        var q = new Queue<string>();
        string line;
        while ((line = r.ReadLine()) != null) {
            // EXPECT-NEXT: clean the queue is dequeued past a fixed size
            q.Enqueue(line);
            if (q.Count > 50) q.Dequeue();
        }
    }

    void Send(List<string> b) {}
    void Handle(string s) {}
}
