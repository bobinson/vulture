public class LdapLookup {
    public Object find(DirContext ctx, String request) {
        // CWE-90: filter built from untrusted request input.
        String user = request;
        return ctx.search("ou=people", "(uid=" + user + ")", null);
    }
}
