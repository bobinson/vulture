func h(req: Request) throws -> Response {
  do { try run() } catch {
    let res = Response(status: .internalServerError)
    // EXPECT-NEXT: finding  swift localizedDescription
    res.body.write(error.localizedDescription)
    return res
  }
}
