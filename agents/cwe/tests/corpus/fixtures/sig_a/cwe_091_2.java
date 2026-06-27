public class AccountLookup {
    public Object find(org.dom4j.Document doc, String request) throws Exception {
        // CWE-91: XPath built by concatenating untrusted request input.
        String acct = request;
        return doc.selectSingleNode("//account[@id='" + acct + "']");
    }
}
