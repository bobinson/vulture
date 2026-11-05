class Lines {
    static final int MAX_LINES = 1000;

    List<String> readAll(BufferedReader reader) throws IOException {
        List<String> lines = new ArrayList<>();
        String line;
        while ((line = reader.readLine()) != null) {
            // EXPECT-NEXT: finding H1 (held-out)
            lines.add(line);
        }
        return lines;
    }

    List<String> readCapped(BufferedReader reader) throws IOException {
        List<String> lines = new ArrayList<>();
        String line;
        while ((line = reader.readLine()) != null) {
            if (lines.size() >= MAX_LINES) {
                break;
            }
            // EXPECT-NEXT: clean H3 (held-out, capped)
            lines.add(line);
        }
        return lines;
    }

    List<String> copy(List<String> names) {
        List<String> out = new ArrayList<>();
        for (String s : names) {
            // EXPECT-NEXT: clean N16 (held-out)
            out.add(s);
        }
        return out;
    }
}
