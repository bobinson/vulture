import org.owasp.esapi.ESAPI;

public class LdapLookup {
    public Object find(DirContext ctx, String request) {
        // Safe: input neutralized with encodeForLDAP before use.
        String user = ESAPI.encoder().encodeForLDAP(request);
        return ctx.search("ou=people", "(uid=" + user + ")", null);
    }
}
