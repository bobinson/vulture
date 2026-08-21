package shop.web;

public class HandlerFactory {

    public Object build(HttpServletRequest request) throws Exception {
        String cls = request.getParameter("handler");
        return Class.forName(cls);
    }
}
