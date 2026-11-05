void h(HttpServletResponse resp) throws IOException {
  try { run(); } catch (IOException e) {
    // EXPECT-NEXT: finding  java writer getMessage
    resp.getWriter().write(e.getMessage());
  }
}
