public async Task H(HttpContext ctx) {
  try { Run(); } catch (Exception ex) {
    // EXPECT-NEXT: finding  cs writeasjson raw
    await ctx.Response.WriteAsJsonAsync(new { error = ex.InnerException })
  }
}
