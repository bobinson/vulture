final class LedgerHandler {
  func load(_ id: String) -> Outcome {
    let o = Outcome()
    do { try store.read(id) } catch { o.error = error.localizedDescription }
    return o
  }
  func show(_ req: Request, _ res: Response, id: String) {
    let outcome = load(id)
    res.send(outcome.error ?? "") // EXPECT: finding tp
  }
}
