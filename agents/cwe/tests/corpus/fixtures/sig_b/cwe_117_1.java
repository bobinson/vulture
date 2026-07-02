public class SearchController {
    public void handleSearch(HttpServletRequest request) {
        // CWE-117: raw search term concatenated into the log line (CRLF injection).
        String term = request.getParameter("q");
        logger.warn("search performed for term=" + term);
    }
}
