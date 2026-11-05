data class Outcome(val ok: Boolean, val error: String?)

fun load(id: String): Outcome = try {
    store.read(id); Outcome(true, null)
} catch (e: Exception) {
    Outcome(false, e.message)
}

suspend fun show(call: ApplicationCall, id: String) {
    val outcome = load(id)
    call.respondText(outcome.error ?: "") // EXPECT: finding tp-positional
}
