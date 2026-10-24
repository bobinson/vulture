func handle(req: Request, res: Response) {
    do { try svc.load() } catch {
        // EXPECT-NEXT: finding  Swift implicit binding localizedDescription
        res.send(error.localizedDescription)
    }
}
