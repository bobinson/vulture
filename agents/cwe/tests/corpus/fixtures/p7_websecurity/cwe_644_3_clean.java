public class Banner {
    void write(HttpServletRequest request, HttpServletResponse resp) throws IOException {
        resp.getWriter().print(response.getHeader("X-Trace"));
    }
}
