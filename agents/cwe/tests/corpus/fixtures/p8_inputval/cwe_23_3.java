class ArchiveUnpacker {
    void unpack(InputStream stream, File destDir) throws IOException {
        ZipInputStream zis = new ZipInputStream(stream);
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File out = new File(destDir, entry.getName());
            copy(zis, out);
        }
    }
}
