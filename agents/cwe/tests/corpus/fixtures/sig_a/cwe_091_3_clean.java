import javax.xml.xpath.XPath;

public class RoleLookup {
    public Object roles(XPath xpath, org.w3c.dom.Document doc, String request) throws Exception {
        // Safe: XPathVariableResolver binds the value; expression is constant.
        xpath.setXPathVariableResolver(v -> request);
        return xpath.compile("//user[@name=$name]/role");
    }
}
