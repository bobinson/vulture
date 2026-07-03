public class AccountLookup {
    public Object find(org.dom4j.Document doc, String request) throws Exception {
        // Safe: constant XPath with a dom4j variable bound from the input.
        org.dom4j.XPath xp = doc.createXPath("//account[@id=$id]");
        xp.setVariables(java.util.Collections.singletonMap("id", request));
        return xp.selectSingleNode(doc);
    }
}
