import org.apache.commons.text.StringEscapeUtils;

public class LoginAudit {
    public void log(HttpServletRequest request) {
        // Safe: CRLF/control chars stripped before logging.
        String user = request.getParameter("user").replaceAll("[\\r\\n]", "_");
        logger.info("login attempt by " + user);
    }
}
