func handle(req: Request) throws -> Response {
    do { try run() } catch {
        // EXPECT-NEXT: clean  known-gap swift implicit error binding
        return Response(status: .internalServerError, body: .init(string: error.localizedDescription))
    }
    return Response(status: .ok)
}
