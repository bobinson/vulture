// Pins: a host allowlist guard `if (!TRUSTED_HOSTS.contains(URI.create(target).getHost())) throw ...` before CLIENT.send(HttpRequest.newBuilder(...).build(), ...).
class RelayService {
    private static final HttpClient CLIENT = HttpClient.newHttpClient();
    private static final Set<String> TRUSTED_HOSTS = Set.of("api.example.test");

    HttpResponse<String> relay(HttpServletRequest request) throws Exception {
        String target = request.getParameter("u");
        if (!TRUSTED_HOSTS.contains(URI.create(target).getHost())) throw new IllegalArgumentException("blocked host");
        return CLIENT.send(HttpRequest.newBuilder(URI.create(target)).build(), HttpResponse.BodyHandlers.ofString());
    }
}
