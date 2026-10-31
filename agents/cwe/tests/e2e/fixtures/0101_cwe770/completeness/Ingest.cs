class Ingest {
    List<string> Slurp(StreamReader reader) {
        var lines = new List<string>();
        string line;
        while ((line = reader.ReadLine()) != null) {
            // EXPECT-NEXT: finding csharp ReadLine
            lines.Add(line);
        }
        return lines;
    }
}
