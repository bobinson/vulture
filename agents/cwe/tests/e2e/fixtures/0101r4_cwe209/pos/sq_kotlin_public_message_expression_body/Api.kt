fun toPublicMessage(e: Throwable): String = e.message ?: e.toString()

suspend fun save(call: ApplicationCall) {
    try {
        repo.save()
    } catch (e: Exception) {
        call.respondText(toPublicMessage(e)) // EXPECT: finding tp-kotlin-defined-public-expression-body
    }
}
