public class Site extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            service.save(req.getParameter("v"));
        } catch (ValidationException e) {
            resp.getWriter().write(e.getCause().getMessage()); // EXPECT: finding tp-java-typed-get-cause
        }
    }
}
