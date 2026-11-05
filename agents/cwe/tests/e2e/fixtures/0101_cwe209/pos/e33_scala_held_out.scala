def h(resp: HttpServletResponse): Unit = {
  try { run() } catch {
    case NonFatal(t) =>
      // EXPECT-NEXT: finding  scala held out
      resp.getWriter.write(t.getMessage)
  }
}
