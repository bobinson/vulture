class Site {
  void get(HttpServletResponse resp) throws IOException {
    try {
      service.apply();
    } catch (InputValidationException e) {
      resp.getWriter().write(e.getMessage()); // EXPECT: clean tg-java-typed-catch
    }
  }
}
