// Pins: new URL(target).openConnection() where target := request.getParameter("u"); openConnection on a URL carrier is the sink.
class PreviewService {
    private static final Set<String> TRUSTED_HOSTS = Set.of("api.example.test");

    URLConnection preview(HttpServletRequest request) throws IOException {
        String target = request.getParameter("u");
        return new URL(target).openConnection();
    }
}
