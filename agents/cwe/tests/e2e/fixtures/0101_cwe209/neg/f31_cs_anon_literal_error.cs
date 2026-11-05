public async Task Invoke(HttpContext ctx) {
  // EXPECT-NEXT: clean  cs anon literal error
  await ctx.Response.WriteAsJsonAsync(new { error = "Unauthorized" });
}
