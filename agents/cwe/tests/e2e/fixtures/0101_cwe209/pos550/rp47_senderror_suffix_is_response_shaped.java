public class Ctl {
    void handle(HttpServletResponse response) throws IOException {
        try {
            run();
        } catch (Exception e) {
            // EXPECT-NEXT: finding check=cwe.info_exposure.server_error_message  sendError suffix is response-shaped
            response.sendError(500, e.getMessage());
        }
    }
}
