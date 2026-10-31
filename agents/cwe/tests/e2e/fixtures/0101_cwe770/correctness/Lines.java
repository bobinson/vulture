class L {
    List<String> all(Scanner sc) {
        List<String> lines = new ArrayList<>();
        while (sc.hasNextLine()) {
            // EXPECT-NEXT: finding java Scanner
            lines.add(sc.nextLine());
        }
        return lines;
    }
    List<byte[]> chunks(InputStream in) throws IOException {
        List<byte[]> out = new ArrayList<>();
        byte[] buf = new byte[4096];
        int n = in.read(buf);
        while (n > 0) {
            // EXPECT-NEXT: finding relational header, read in body
            out.add(Arrays.copyOf(buf, n));
            n = in.read(buf);
        }
        return out;
    }
    List<String> doWhile(BufferedReader r) throws IOException {
        List<String> out = new ArrayList<>();
        String line;
        do {
            line = r.readLine();
            // EXPECT-NEXT: finding do-while
            out.add(line);
        } while (line != null);
        return out;
    }
    List<String> oneLine(BufferedReader reader) throws IOException {
        List<String> lines = new ArrayList<>();
        String line;
        // EXPECT-NEXT: finding single-line loop
        while ((line = reader.readLine()) != null) lines.add(line);
        return lines;
    }
}
