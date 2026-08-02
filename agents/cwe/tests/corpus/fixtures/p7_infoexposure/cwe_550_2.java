public class ReportServlet extends HttpServlet {
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    try {
      render(request);
    } catch (IOException e) {
      response.sendError(500, e.getMessage());
    }
  }
}
