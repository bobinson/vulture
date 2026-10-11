public async Task H(HttpContext context) {
  try { Run(); } catch (InvalidOperationException ex) {
    // EXPECT-NEXT: finding  csharp held-out
    await context.Response.WriteAsync(ex.Message);
  }
}
