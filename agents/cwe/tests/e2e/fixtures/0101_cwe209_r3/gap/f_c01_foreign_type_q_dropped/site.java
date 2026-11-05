class LedgerServlet extends HttpServlet {
  static Outcome failed(String msg) { Outcome o = new Outcome(); o.reason = msg; return o; }
  Outcome load(String id) {
    try { store.read(id); return new Outcome(); }
    catch (Exception e) { return new Outcome(false, e.getMessage()); }
  }
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    Outcome outcome = load(req.getParameter("id"));
    resp.getWriter().write(outcome.getError()); // EXPECT: clean tp-positional-ctor
  }
}
