class Site {
  void get(HttpServletResponse resp) throws IOException {
    try {
      dao.load();
    } catch (SQLException e) {
      resp.getWriter().write(e.getMessage()); // EXPECT: finding tp-java-typed-sqlexception
    }
  }
}
