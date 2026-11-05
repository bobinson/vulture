class Api {
  void proxy(HttpServletResponse resp, String id) throws IOException {
    try {
      resp.getWriter().write(rest.getForObject(BILLING + id, String.class));
    } catch (HttpClientErrorException.Forbidden e) {
      resp.getWriter().write(e.getMessage()); // EXPECT: finding tp-java-outbound-forbidden
    }
  }
}
