class Site {
  void get(HttpServletResponse resp) throws IOException {
    try {
      service.apply();
    } catch (InputValidationException e) {
      resp.getWriter().write(e.toString() + e.getCause()); // EXPECT: finding tp-java-typed-plus-cause
    }
  }
}
