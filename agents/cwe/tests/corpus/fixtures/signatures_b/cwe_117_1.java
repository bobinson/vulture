public class LoginAudit {
    public void log(HttpServletRequest request) {
        // CWE-117: untrusted parameter logged without neutralization.
        String user = request.getParameter("user");
        logger.info("login attempt by " + user);
    }
}
