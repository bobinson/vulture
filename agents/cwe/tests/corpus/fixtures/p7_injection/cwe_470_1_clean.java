package shop.web;

import java.util.Map;

public class HandlerFactory {
    private static final Map<String, String> ALLOWED_HANDLERS = Map.of(
        "csv", "shop.web.CsvHandler", "pdf", "shop.web.PdfHandler");

    public Object build(HttpServletRequest request) throws Exception {
        String cls = ALLOWED_HANDLERS.get(request.getParameter("handler"));
        return Class.forName(cls);
    }
}
