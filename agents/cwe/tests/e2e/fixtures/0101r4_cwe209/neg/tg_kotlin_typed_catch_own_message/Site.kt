fun Route.items() {
    post("/items") {
        try {
            service.save(call.receive())
        } catch (e: InputValidationException) {
            call.respondText(e.message ?: "", status = HttpStatusCode.BadRequest) // EXPECT: clean tg-kotlin-own-message
        }
    }
}
