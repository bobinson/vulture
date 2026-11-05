class Api {
  void sync(HttpServletResponse resp) throws IOException {
    try {
      billing.push();
    } catch (BillingClient.ValidationException e) {
      resp.getWriter().write(e.getMessage()); // EXPECT: finding tp-java-client-qualified-validation
    }
  }
}
