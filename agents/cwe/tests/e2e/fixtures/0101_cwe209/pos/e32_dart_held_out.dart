Future<Response> h(Request req) async {
  try { await run(); } catch (e) {
    final res = Response.internalServerError();
    // EXPECT-NEXT: finding  dart held out
    req.response.write(e.toString());
    return res;
  }
}
