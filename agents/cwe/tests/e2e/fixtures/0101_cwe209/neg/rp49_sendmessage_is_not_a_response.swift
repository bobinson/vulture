func relay(_ payload: [String: Any], with session: WCSession) async throws {
    try await withCheckedThrowingContinuation { done in
        // EXPECT-NEXT: clean  sendMessage is not a response-shaped verb
        session.sendMessage(payload, replyHandler: { _ in
            done.resume()
        }, errorHandler: { error in
            done.resume(throwing: error)
        })
    }
}
