fun Route.items() {
    post("/items") {
        try {
            service.save(call.receive())
        } catch (e: ValidationException) {
            call.respondText(e.dbError.message ?: "", status = HttpStatusCode.BadRequest) // EXPECT: finding tp-kotlin-own-db-member
        }
    }
}
