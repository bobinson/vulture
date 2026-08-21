class ArchiveUnpacker {
    void unpack(InputStream stream, File destDir) throws IOException {
        ZipInputStream zis = new ZipInputStream(stream);
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File out = new File(destDir, entry.getName());
            if (!out.getCanonicalPath().startsWith(destDir.getCanonicalPath())) {
                throw new IOException("entry escapes the extraction root");
            }
            copy(zis, out);
        }
    }
}
