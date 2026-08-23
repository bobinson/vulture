public final class ManifestReader {
    public Document read(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setExpandEntityReferences(false);
        return factory.newDocumentBuilder().parse(in);
    }
}
