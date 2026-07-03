import org.owasp.esapi.ESAPI;

public class GroupLookup {
    public Object members(DirContext ctx, javax.servlet.http.HttpServletRequest request) {
        // Safe: request value neutralized with encodeForLDAP before the filter.
        String group = ESAPI.encoder().encodeForLDAP(request.getParameter("group"));
        return ctx.search("ou=groups", "(cn=" + group + ")", null);
    }
}
