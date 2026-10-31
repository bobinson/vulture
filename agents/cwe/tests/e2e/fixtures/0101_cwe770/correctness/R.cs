class R {
    async Task<List<string>> All(StreamReader reader) {
        var lines = new List<string>();
        string line;
        while ((line = await reader.ReadLineAsync()) != null) {
            // EXPECT-NEXT: finding C# async read
            lines.Add(line);
        }
        return lines;
    }
    async Task<List<byte[]>> Chunks(NetworkStream stream) {
        var chunks = new List<byte[]>();
        while (true) {
            var buf = new byte[4096];
            int n = await stream.ReadAsync(buf, 0, buf.Length);
            if (n == 0) break;
            // EXPECT-NEXT: finding C# ReadAsync
            chunks.Add(buf);
        }
        return chunks;
    }
}
