class R {
    void read(java.io.BufferedReader reader) throws Exception {
        String line;
        while ((line = reader.readLine()) != null) {
            final java.util.List<String> parts = new java.util.ArrayList<>();
            // EXPECT-NEXT: clean qualified generic type, declared in the body
            parts.add(line);
            process(parts);
        }
    }
}
