public class SearchController {
    public void handleSearch(HttpServletRequest request) {
        // Safe: CR/LF stripped from the term before it reaches the log line.
        String term = request.getParameter("q").replaceAll("[\\r\\n]", "_");
        logger.warn("search performed for term=" + term);
    }
}
