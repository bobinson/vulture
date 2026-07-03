public class XPathLookup {
    public Object find(Document doc, String request) throws Exception {
        // CWE-91: XPath expression concatenated from untrusted input.
        String user = request;
        return doc.selectNodes("//user[@name='" + user + "']");
    }
}
