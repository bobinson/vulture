public class GroupLookup {
    public Object members(DirContext ctx, javax.servlet.http.HttpServletRequest request) {
        // CWE-90: LDAP filter concatenated from a request parameter.
        String group = request.getParameter("group");
        return ctx.search("ou=groups", "(cn=" + group + ")", null);
    }
}
