class One {
    List<String> read(BufferedReader reader) throws IOException {
        List<String> lines = new ArrayList<>();
        String line;
        // EXPECT-NEXT: finding one-line loop
        while ((line = reader.readLine()) != null) lines.add(line);
        return lines;
    }
}
