suspend fun show(call: ApplicationCall, id: String) {
    try { store.read(id) } catch (e: Exception) {
        respondError(call, HttpStatusCode.InternalServerError, e.message ?: "") // EXPECT: finding tp-C-kotlin-call-not-peer-word
        sendJsonError(conn, 500, e.message) // probe tp-C-kotlin
    }
}
