// Pins: Runtime.getRuntime().exec(cmd) where cmd := request.getParameter("cmd"); strong exec sink on a request accessor value.
class OpsService {
    private static final Set<String> ALLOWED_CMDS = Set.of("uptime", "df");

    Process launch(HttpServletRequest request) throws IOException {
        String cmd = request.getParameter("cmd");
        return Runtime.getRuntime().exec(cmd);
    }
}
