public class XPathLookup {
    public Object find(Document doc, String request) throws Exception {
        // Safe: XPathVariableResolver binds the value, no concatenation.
        xpath.setXPathVariableResolver(new MyResolver(request));
        return doc.selectNodes("//user[@name=$user]");
    }
}
