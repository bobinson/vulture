// Feature 0101, CWE-778 Concept B: a Kotlin `val` bound to a boolean expression
// is a decision and reports; a `val` bound to a plain value names an outcome.

class Gate {
    fun handle(user: User, call: Call) {
        val forbidden = !user.isAdmin // EXPECT: finding
        if (check(user)) {
            call.respond(1)
        }
    }

    fun handleOwner(user: User, call: Call) {
        val unauthorized = user.owner != call.owner || user.suspended // EXPECT: finding
        if (check(user)) {
            call.respond(1)
        }
    }

    companion object {
        const val FORBIDDEN = "reason.denied" // EXPECT: clean
    }
}
