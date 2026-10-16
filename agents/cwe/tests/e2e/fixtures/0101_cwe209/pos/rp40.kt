fun Route.items() {
    get("/x") {
        try { svc.load() } catch (e: Exception) {
            // EXPECT-NEXT: finding
            call.respondText(e.message ?: "error")
        }
    }
}
