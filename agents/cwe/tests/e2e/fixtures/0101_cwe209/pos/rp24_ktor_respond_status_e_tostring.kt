fun Route.x() {
    get("/") {
        try { run() } catch (e: Exception) {
            // EXPECT-NEXT: finding  ktor respond status e toString
            call.respond(HttpStatusCode.InternalServerError, e.toString())
        }
    }
}
