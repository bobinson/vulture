// Pins: CLIENT.send(HttpRequest.newBuilder(URI.create(target)).build(), ...) where target := request.getParameter("u"); send with request/uri carriers.
class RelayService {
    private static final HttpClient CLIENT = HttpClient.newHttpClient();
    private static final Set<String> TRUSTED_HOSTS = Set.of("api.example.test");

    HttpResponse<String> relay(HttpServletRequest request) throws Exception {
        String target = request.getParameter("u");
        return CLIENT.send(HttpRequest.newBuilder(URI.create(target)).build(), HttpResponse.BodyHandlers.ofString());
    }
}
