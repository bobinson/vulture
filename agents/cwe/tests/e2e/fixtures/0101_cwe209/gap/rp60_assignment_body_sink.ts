export async function handleQuote(ctx) {
  try {
    await priceQuote(ctx.request.body);
  } catch (err) {
    // EXPECT-NEXT: clean  known-gap an assignment to a response body is not a member write
    ctx.body = { error: err.message };
  }
}
