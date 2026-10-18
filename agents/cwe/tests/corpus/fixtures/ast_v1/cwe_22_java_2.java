// Pins: new FileInputStream(DOC_ROOT + "/" + p) where p := request.getParameter("f") on an HttpServletRequest param (accessor + stream sink).
class DocReader {
    private static final String DOC_ROOT = "/srv/docs";

    InputStream docFor(HttpServletRequest request) throws IOException {
        String p = request.getParameter("f");
        return new FileInputStream(DOC_ROOT + "/" + p);
    }
}
