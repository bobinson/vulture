package x

data class Outcome(val ok: Boolean, val error: String?)

fun load(id: String): Outcome =
    try {
        Outcome(true, null)
    } catch (e: Exception) {
        Outcome(false, e.message)
    }

fun Route.r() {
    get("/x") {
        val out = load(call.parameters["id"]!!)
        if (!out.ok) call.respond(HttpStatusCode.InternalServerError, mapOf("error" to out.error)) // probe tp-kt-K
        call.respond(HttpStatusCode.InternalServerError, out) // EXPECT: clean tp-kt-whole
    }
}
