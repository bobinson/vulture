class Site {
  void post(HttpServletResponse resp) throws IOException {
    try {
      dao.save();
    } catch (InputValidationException e) {
      resp.getWriter().write(e.sqlError.getMessage()); // EXPECT: finding tp-java-own-field-sql-error
    }
  }
}
