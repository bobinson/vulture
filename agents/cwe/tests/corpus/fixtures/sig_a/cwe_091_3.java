import javax.xml.xpath.XPath;

public class RoleLookup {
    public Object roles(XPath xpath, org.w3c.dom.Document doc, String request) throws Exception {
        // CWE-91: XPath expression compiled from untrusted input.
        String user = request;
        return xpath.compile("//user[@name='" + user + "']/role");
    }
}
