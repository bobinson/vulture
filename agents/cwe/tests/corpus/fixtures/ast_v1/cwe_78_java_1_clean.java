// Pins: an allowlist guard `if (!ALLOWED_CMDS.contains(cmd)) throw ...` on the same name before Runtime.getRuntime().exec(cmd).
class OpsService {
    private static final Set<String> ALLOWED_CMDS = Set.of("uptime", "df");

    Process launch(HttpServletRequest request) throws IOException {
        String cmd = request.getParameter("cmd");
        if (!ALLOWED_CMDS.contains(cmd)) throw new IllegalArgumentException("command not allowed");
        return Runtime.getRuntime().exec(cmd);
    }
}
