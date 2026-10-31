fun load(id: String): Outcome {
    try {
        db.touch(id)
    } catch (e: Exception) {
        metrics.record(Failure(e))
    }
    return remote.lookup(id)
}

fun Route.r() {
    get("/x") {
        val out = load(call.parameters["id"]!!)
        call.respond(HttpStatusCode.BadGateway, mapOf("error" to out.error)) // EXPECT: clean clean-Q-sideeffect-kt
    }
}
