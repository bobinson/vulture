fun Route.items() {
    get("/f") {
        try {
            call.respondText(File(call.parameters["p"]!!).readText())
        } catch (e: UnauthorizedAccessException) {
            call.respondText(e.message ?: "", status = HttpStatusCode.Forbidden) // EXPECT: finding tp-kotlin-unauthorized-access
        }
    }
}
