fun Route.items() {
    post("/items") {
        try {
            service.save(call.receive())
        } catch (e: ValidationException) {
            call.respondText(e.cause.toString(), status = HttpStatusCode.BadRequest) // EXPECT: finding tp-kotlin-typed-cause
        }
    }
}
