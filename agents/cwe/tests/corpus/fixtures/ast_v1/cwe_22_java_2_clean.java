// Pins: a `..` rejection guard `if (p.contains("..")) throw ...` on the same name before new FileInputStream(DOC_ROOT + "/" + p).
class DocReader {
    private static final String DOC_ROOT = "/srv/docs";

    InputStream docFor(HttpServletRequest request) throws IOException {
        String p = request.getParameter("f");
        if (p.contains("..")) throw new IllegalArgumentException("bad path");
        return new FileInputStream(DOC_ROOT + "/" + p);
    }
}
