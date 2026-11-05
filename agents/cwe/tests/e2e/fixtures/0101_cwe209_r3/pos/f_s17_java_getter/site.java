class LedgerServlet extends HttpServlet {
  Outcome load(String id) {
    Outcome o = new Outcome();
    try { store.read(id); } catch (Exception e) { o.setError(e.getMessage()); }
    return o;
  }
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    Outcome outcome = load(req.getParameter("id"));
    resp.getWriter().write(outcome.getError()); // EXPECT: finding tp-getter
  }
}
