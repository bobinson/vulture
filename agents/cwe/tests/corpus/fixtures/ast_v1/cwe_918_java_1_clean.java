// Pins: a host allowlist guard `if (!TRUSTED_HOSTS.contains(new URL(target).getHost())) throw ...` before new URL(target).openConnection().
class PreviewService {
    private static final Set<String> TRUSTED_HOSTS = Set.of("api.example.test");

    URLConnection preview(HttpServletRequest request) throws IOException {
        String target = request.getParameter("u");
        if (!TRUSTED_HOSTS.contains(new URL(target).getHost())) throw new IllegalArgumentException("blocked host");
        return new URL(target).openConnection();
    }
}
