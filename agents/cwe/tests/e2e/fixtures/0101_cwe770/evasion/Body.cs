using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;

public class Reader
{
    public List<byte[]> Drain(NetworkStream stream)
    {
        var chunks = new List<byte[]>();
        while (true)
        {
            var buf = new byte[4096];
            int n = stream.Read(buf, 0, buf.Length);
            if (n == 0) break;
            // EXPECT-NEXT: finding E19 Allman braces (C# house style)
            chunks.Add(buf);
        }
        return chunks;
    }

    public byte[] Copy(Stream input)
    {
        var ms = new MemoryStream();
        var buf = new byte[8192];
        int n;
        while ((n = input.Read(buf, 0, buf.Length)) > 0) {
            // EXPECT-NEXT: finding E20 MemoryStream.Write sink
            ms.Write(buf, 0, n);
        }
        return ms.ToArray();
    }

    public List<string> Lines(TextReader reader) {
        var lines = new List<string>();
        string line;
        do {
            line = reader.ReadLine();
            // EXPECT-NEXT: finding E21 do/while is not a loop header
            if (line != null) lines.Add(line);
        } while (line != null);
        return lines;
    }
}
