func price(_ req: Request) -> Response {
    do {
        return try quote(req)
    } catch {
        // EXPECT-NEXT: clean  known-gap a response initialiser is not a member write
        return Response(status: .internalServerError, body: .init(string: "\(error)"))
    }
}
