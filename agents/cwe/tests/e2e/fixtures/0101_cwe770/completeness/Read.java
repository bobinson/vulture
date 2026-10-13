class Read {
    byte[] slurp(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1) {
            // EXPECT-NEXT: finding java stream to BAOS
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }
    List<String> configLines(BufferedReader cfg) throws IOException {
        List<String> out = new ArrayList<>();
        String l;
        while ((l = cfg.readLine()) != null) {
            // EXPECT-NEXT: finding a reader parameter pulled line by line; its name cannot say it is a local file
            out.add(l);
        }
        return out;
    }
    void index(Map<String,Integer> m, List<String> keys) {
        for (String k : keys) {
            // EXPECT-NEXT: clean in-memory
            m.put(k, 1);
        }
    }
}
