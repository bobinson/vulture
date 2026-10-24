data class Outcome(val error: String? = null)

fun load(id: String): Outcome = try {
    store.read(id); Outcome()
} catch (e: Exception) {
    Outcome(error = e.message)
}

suspend fun show(call: ApplicationCall, id: String) {
    val outcome = load(id)
    call.respondText(outcome.error ?: "") // EXPECT: finding tp
}
